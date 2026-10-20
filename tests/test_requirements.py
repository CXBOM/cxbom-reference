"""Hash-locked requirement files and the post-install check (spec 3, 12, QC.1).

Owner: ATACE Working Group.
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import sysconfig
from types import SimpleNamespace
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
REQ = ROOT / "requirements"
LOCKS = (REQ / "core.txt", REQ / "emit.txt", REQ / "build.txt", ROOT / "requirements-dev.txt",
         REQ / "pip.txt", REQ / "pip-build.txt", REQ / "drift.txt")
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

sys.path.insert(0, str(ROOT / "scripts"))
import verify_env  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workflow_helpers import load_workflow  # noqa: E402


def logical_lines(path: Path) -> list[str]:
    joined = path.read_text(encoding="utf-8").replace("\\\n", " ")
    return [ln.strip() for ln in joined.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def pins(path: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for ln in logical_lines(path):
        name, version = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;*]+)", ln).groups()
        out.setdefault(canonicalize_name(name), set()).add(version)
    return out


def test_every_lock_line_is_pinned_and_hashed():
    for path in LOCKS:
        lines = logical_lines(path)
        assert lines, path.name
        for ln in lines:
            head, *hashes = re.split(r"\s+--hash=", ln)
            assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*==[^\s;*]+( ; .+)?", head.strip()), (path.name, ln)
            assert hashes and all(re.fullmatch(r"sha256:[0-9a-f]{64}", h.strip()) for h in hashes), (path.name, ln)


def test_core_lock_satisfies_pyproject():
    core = pins(REQ / "core.txt")
    for dep in PROJECT["project"]["dependencies"]:
        req = Requirement(dep)
        name = canonicalize_name(req.name)
        assert name in core, name
        assert all(v in req.specifier for v in core[name]), name


def test_emit_lock_is_tokenizers_alone_within_the_extra_range():
    (extra,) = PROJECT["project"]["optional-dependencies"]["emit"]
    emit = pins(REQ / "emit.txt")
    assert set(emit) == {"tokenizers"}
    assert all(v in Requirement(extra).specifier for v in emit["tokenizers"])


def test_the_allowlist_names_the_locked_tokenizers():
    (version,) = pins(REQ / "emit.txt")["tokenizers"]
    assert verify_env.load_allowed(verify_env.ALLOW) == {
        f"tokenizers {version} requires huggingface-hub, which is not installed."}


def test_the_build_backend_is_the_locked_hatchling():
    assert PROJECT["build-system"]["requires"] == ["hatchling==1.32.4"]
    assert pins(REQ / "build.txt")["hatchling"] == {"1.32.4"}


def test_the_dev_lock_tests_the_versions_that_ship():
    dev = pins(ROOT / "requirements-dev.txt")
    for path in (REQ / "core.txt", REQ / "emit.txt", REQ / "build.txt"):
        for name, versions in pins(path).items():
            assert dev.get(name) == versions, (path.name, name)


@pytest.mark.skipif(not (ROOT / ".github" / "workflows" / "ci.yml").is_file(),
                    reason="CI workflows live in the development repository")
def test_ci_installs_the_dev_lock_without_resolving_and_then_checks_it():
    # Ruling P6: pip must never resolve against the live index in CI, and every
    # third-party action runs from a reviewed commit, never a movable tag.
    ci_path = ROOT / ".github" / "workflows" / "ci.yml"
    ci = ci_path.read_text(encoding="utf-8")
    # Parsed, not matched line by line. A regex over the text passed while the
    # unquoted ":all: " made the file invalid YAML, which GitHub refuses before
    # any job starts, so CI failed in 0 s and this test stayed green. Loaded
    # through load_workflow, which also refuses a duplicate key, so a second
    # `run:` cannot replace a step this test reads.
    runs = [step["run"].strip() for job in load_workflow(ci_path)["jobs"].values()
            for step in job["steps"] if "run" in step]
    install = "pip install --no-deps --require-hashes --only-binary :all: -r requirements-dev.txt"
    assert install in runs and "pip check" in runs
    # The tests job deselects the site_tooling marker (its tests need a browser
    # and run in the site-tooling job); the install and check still come first.
    assert runs.index(install) < runs.index("pip check") < runs.index('python -m pytest -q -rfEs -m "not site_tooling"')
    assert not [r for r in runs if r.startswith("pip install") and r != install]
    uses = re.findall(r"uses:\s*(\S+)", ci)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses), uses


PIP_LINE = "tokenizers 0.23.2 requires huggingface-hub, which is not installed."


def test_verify_env_accepts_only_the_allowed_line():
    allowed = {PIP_LINE}
    assert verify_env.unexpected("No broken requirements found.\n", set()) == []
    assert verify_env.unexpected(PIP_LINE + "\n", allowed) == []
    assert verify_env.unexpected(PIP_LINE + "\n", set()) == [PIP_LINE]
    other = "cxbom 0.3.0.dev0 requires cryptography, which is not installed."
    assert verify_env.unexpected(f"{PIP_LINE}\n{other}\n", allowed) == [other]
    near = "tokenizers 0.23.2 has requirement huggingface-hub<2.0,>=0.16.4, but you have huggingface-hub 2.1.0."
    assert verify_env.unexpected(near + "\n", allowed) == [near]


PURELIB = Path(sysconfig.get_paths()["purelib"]).resolve()


def run_problems(monkeypatch, *, rc=0, out=verify_env.CLEAN + "\n", err="", emit=False,
                 hub=False, cxbom=PURELIB / "cxbom" / "__init__.py", tokenizers=True):
    """problems() with pip check and module lookup replaced by the given outcome."""
    monkeypatch.setattr(verify_env.subprocess, "run",
                        lambda args, **kw: subprocess.CompletedProcess(args, rc, out, err))
    specs = {
        "huggingface_hub": SimpleNamespace(origin="hub") if hub else None,
        "cxbom": SimpleNamespace(origin=str(cxbom)) if cxbom else None,
        "tokenizers": SimpleNamespace(origin="tokenizers") if tokenizers else None,
    }
    monkeypatch.setattr(verify_env.importlib.util, "find_spec", lambda name, *a, **kw: specs[name])
    return verify_env.problems(emit)


def test_a_complete_environment_passes(monkeypatch):
    # The baseline every failing case below departs from by one field.
    assert run_problems(monkeypatch) == []
    assert run_problems(monkeypatch, emit=True) == []


def test_the_allowed_line_passes_only_in_an_emit_install(monkeypatch):
    assert run_problems(monkeypatch, rc=1, out=PIP_LINE + "\n", emit=True) == []
    errs = run_problems(monkeypatch, rc=1, out=PIP_LINE + "\n", emit=False)
    assert f"pip check: {PIP_LINE}" in errs


@pytest.mark.parametrize("rc, out, emit", [
    (1, "", False),                          # "No module named pip" prints nothing on stdout
    (1, "", True),
    (2, verify_env.CLEAN + "\n", False),     # any exit code other than 0 or 1
    (2, PIP_LINE + "\n", True),
    (0, "", False),                          # exit 0 must still print the clean line
    (0, PIP_LINE + "\n", True),              # the allowed line is accepted only with exit 1
    (1, verify_env.CLEAN + "\n", True),
], ids=["empty-exit1", "empty-exit1-emit", "exit2", "exit2-allowed", "empty-exit0",
        "allowed-exit0", "clean-exit1"])
def test_every_other_pip_check_outcome_fails(monkeypatch, rc, out, emit):
    errs = run_problems(monkeypatch, rc=rc, out=out, err="/x/python: No module named pip\n", emit=emit)
    assert any(f"exit {rc}" in e and "No module named pip" in e for e in errs), errs


def test_an_importable_hub_fails(monkeypatch):
    errs = run_problems(monkeypatch, rc=1, out=PIP_LINE + "\n", emit=True, hub=True)
    assert errs == ["huggingface_hub is installed. The emit lock installs tokenizers without it"]


def test_cxbom_outside_site_packages_fails(monkeypatch):
    expected = ["cxbom is not installed in this environment's site-packages"]
    assert run_problems(monkeypatch, cxbom=ROOT / "cxbom" / "__init__.py") == expected
    assert run_problems(monkeypatch, cxbom=None) == expected


def test_an_emit_install_without_tokenizers_fails(monkeypatch):
    assert run_problems(monkeypatch, emit=True, tokenizers=False) == [
        "tokenizers is missing. Install requirements/emit.txt"]
    assert run_problems(monkeypatch, emit=False, tokenizers=False) == []


def test_main_exit_code_and_verdict_follow_problems(monkeypatch, capsys):
    monkeypatch.setattr(verify_env, "problems", lambda emit: [] if emit else ["broken"])
    assert verify_env.main(["--emit"]) == 0
    assert capsys.readouterr().out == "verify_env: ok\n"
    assert verify_env.main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == "verify_env: FAILED\n" and captured.err == "verify_env: broken\n"


def test_a_venv_without_pip_fails_for_real(tmp_path):
    # The reviewer's reproduction: uv creates venvs without pip, and cxbom copied
    # into site-packages with no dependencies used to print "verify_env: ok".
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True, timeout=120)
    py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    purelib = subprocess.run([str(py), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                             capture_output=True, text=True, check=True, timeout=60).stdout.strip()
    shutil.copytree(ROOT / "cxbom", Path(purelib) / "cxbom", ignore=shutil.ignore_patterns("__pycache__"))
    r = subprocess.run([str(py), str(ROOT / "scripts" / "verify_env.py")],
                       capture_output=True, text=True, cwd=tmp_path, timeout=120)
    assert r.returncode == 1 and r.stdout == "verify_env: FAILED\n"
    assert "pip check did not pass (exit 1, 0 stdout lines" in r.stderr and "No module named pip" in r.stderr


def pinned_uv() -> str:
    """The uv on PATH, refused unless it is the version requirements/drift.txt pins by hash."""
    uv = shutil.which("uv")
    assert uv, "CXBOM_LOCK_DRIFT=1 needs uv on PATH"
    (uv_pin,) = pins(REQ / "drift.txt")["uv"]
    version = subprocess.run([uv, "--version"], capture_output=True, text=True, timeout=60).stdout
    # The PyPI wheel prints "uv 0.8.14" alone and Homebrew appends a build note,
    # so compare whole words. A prefix test with a trailing space refused the
    # very uv requirements/drift.txt installs, and 0.8.140 must not pass as 0.8.14.
    assert version.split()[:2] == ["uv", uv_pin], (version, uv_pin)
    return uv


@pytest.mark.parametrize("reported, ok", [("uv 0.8.14 (Homebrew 2025-08-28)", True), ("uv 0.8.14", True),
                                          ("uv 0.9.2", False),
                                          ("uv 0.8.140", False), ("", False)])
def test_the_drift_check_refuses_any_uv_but_the_pinned_one(tmp_path, monkeypatch, reported, ok):
    (pin,) = pins(REQ / "drift.txt")["uv"]
    fake = tmp_path / "uv"
    fake.write_text(f"#!/bin/sh\necho '{reported.replace('0.8.14', pin)}'\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    if ok:
        assert pinned_uv() == str(fake)
    else:
        with pytest.raises(AssertionError):
            pinned_uv()


@pytest.mark.skipif(os.environ.get("CXBOM_LOCK_DRIFT") != "1",
                    reason="opt-in drift check: needs uv and the live index. Set CXBOM_LOCK_DRIFT=1")
@pytest.mark.parametrize("lock", LOCKS, ids=lambda p: p.name)
def test_the_lock_regenerates_unchanged(lock, tmp_path):
    """Re-run the committed compile command and require the same pins and hashes.

    uv copies hashes from an existing output file without checking them, so the
    command writes to a fresh file. The committed pins, without their hashes,
    go in as constraints, so versions stay put and every hash comes from the
    live index. A hand-edited hash, pin, or line fails here. It runs in a copy
    of the lock inputs, so the working tree is never rewritten.
    """
    header = lock.read_text(encoding="utf-8").splitlines()[1]
    argv = shlex.split(header.lstrip("# "))
    assert argv[:3] == ["uv", "pip", "compile"] and "--generate-hashes" in argv, header
    assert not {"-U", "--upgrade", "-P", "--upgrade-package"} & set(argv), header
    assert argv[-2] == "-o" and Path(argv[-1]) == lock.relative_to(ROOT), header
    uv = pinned_uv()
    inputs = [*REQ.glob("*.in"), *REQ.glob("*.txt"), ROOT / "requirements-dev.in", ROOT / "requirements-dev.txt"]
    for src in inputs:
        dst = tmp_path / src.relative_to(ROOT)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
    committed = locked(lock)
    (tmp_path / "drift-pins.txt").write_text("\n".join(committed) + "\n", encoding="utf-8")
    cmd = [uv, *argv[1:-1], "drift-out.txt", "-c", "drift-pins.txt", "--no-header", "--no-annotate"]
    # No uv config, so an index override cannot change the result, and no cache,
    # so every hash comes from the live index rather than a local copy.
    env = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"], "UV_NO_CONFIG": "1", "UV_NO_CACHE": "1"}
    r = subprocess.run(cmd, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    assert locked(tmp_path / "drift-out.txt") == committed, f"{lock.name} drifted from its compile command"


def locked(path: Path) -> dict[str, set[str]]:
    """Each lock line's requirement head mapped to its set of hashes."""
    out: dict[str, set[str]] = {}
    for ln in logical_lines(path):
        head, *hashes = re.split(r"\s+--hash=", ln)
        out[head.strip()] = {h.strip() for h in hashes}
    return out
