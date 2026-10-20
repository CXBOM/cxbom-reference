"""Install cxbom from this checkout with hash-locked, offline pip installs (spec 12, 15).

Owner: ATACE Working Group.

Three steps. Only download uses the network.

    python3 scripts/install_cxbom.py download --wheelhouse DIR
    python3 scripts/install_cxbom.py build --wheelhouse DIR --out DIST [--expect-sha256 HEX]
    python3 scripts/install_cxbom.py install --wheelhouse DIR --wheel DIST/cxbom-*.whl --venv DIR [--emit]

download fetches every file named in requirements/core.txt, emit.txt and
build.txt for this interpreter and platform, checked against the lock hashes.
Run it with the interpreter that will run cxbom (inside the agent image on the
Jetson), because pip evaluates lock markers for the running interpreter.

build creates a throwaway venv from the wheelhouse, installs hatchling from
requirements/build.txt, and runs scripts/build_wheel.py. It prints
"<sha256>  <wheel name>" as the only line on stdout, since every step sends
the output of the commands it runs to stderr. With --expect-sha256 it refuses a wheel whose hash
differs, which is how the Jetson proves it built the Mac's wheel.

install creates the venv (which must not exist), installs the core lock, the
emit lock with --emit, and the wheel by a hashed direct reference, each with
--no-deps --require-hashes --no-index, then runs scripts/verify_env.py in it.

With --pip-lock LOCK, download also fetches the pip that LOCK pins, and build
and install force-install it by hash into every venv they create, then refuse
unless `pip --version` reports that version. Without it, each venv keeps the
pip its interpreter bundles, which on Ubuntu 22.04 is pip 22.0.2: old enough
that build_wheel.py refuses to build at all.

The Ubuntu 22.04 CI job downloads both pins and splits them by step, because
the two steps need different pip versions: every build passes
requirements/pip-build.txt (pip 26.2.1, since build_wheel.py refuses a pip
older than 24.0) and every install passes requirements/pip.txt (pip 22.0.2,
the version the Jetson host has, which is what the install path must prove).

Exit 0 on success, 1 on a failed step, 2 on a usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQ = ROOT / "requirements"
CORE, EMIT, BUILD = REQ / "core.txt", REQ / "emit.txt", REQ / "build.txt"
WHEEL_NAME = re.compile(r"^cxbom-[0-9][0-9a-z.]*-py3-none-any\.whl$")
MIN_PYTHON = (3, 10)


class InstallError(RuntimeError):
    """A download, build, install or check step failed."""


def check_python(version_info) -> None:
    if tuple(version_info[:2]) < MIN_PYTHON:
        raise InstallError("cxbom needs Python 3.10 or newer")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download_command(python: str, wheelhouse: Path, pip_lock: Path | None = None) -> list[str]:
    cmd = [python, "-m", "pip", "download", "--no-deps", "--require-hashes", "--only-binary", ":all:",
           "--dest", str(wheelhouse), "-r", str(CORE), "-r", str(EMIT), "-r", str(BUILD)]
    return cmd + (["-r", str(pip_lock)] if pip_lock else [])


def install_command(python: str, wheelhouse: Path, locks: list[Path]) -> list[str]:
    cmd = [python, "-m", "pip", "install", "--no-deps", "--require-hashes", "--only-binary", ":all:",
           "--no-index", "--find-links", str(wheelhouse)]
    for lock in locks:
        cmd += ["-r", str(lock)]
    return cmd


def direct_reference(wheel: Path) -> str:
    """The wheel as a hashed direct reference: the hash on the URL and as an option.

    The option is what --require-hashes enforces. The fragment is what survives
    into the venv. pip fills direct_url.json's archive_info hash from Link.hash,
    a regex over the URL string, so a hash carried only as a requirement option
    is verified at install time and then not recorded. Measured with this exact
    install command on Python 3.10, archive_info for a reference with no
    fragment is {} on pip 22.0.2, 22.2.2, 22.3 and 23.0, because only 23.1 and
    newer hash the archive themselves instead of reading the URL. That is a
    record demo/gonogo.py's wheel-sha256 check cannot read, so it refuses a
    correct install on the pip requirements/pip.txt pins and the Jetson image
    ships. With the fragment, 22.0.2 through 22.3 write hash="sha256=<hex>" and
    23.0 and newer write hashes={"sha256": "<hex>"} as well. Both forms carry
    the same value, so both come from one digest rather than two reads of the
    file.
    """
    if not WHEEL_NAME.fullmatch(wheel.name):
        raise InstallError(f"not a cxbom wheel: {wheel.name}")
    sha = sha256_file(wheel)
    return f"cxbom @ {wheel.resolve().as_uri()}#sha256={sha} --hash=sha256:{sha}\n"


def pip_version(pip_lock: Path) -> str:
    """The one version a pip lock pins. Anything else in the lock is refused."""
    joined = pip_lock.read_text(encoding="utf-8").replace("\\\n", " ")
    lines = [ln.strip() for ln in joined.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    pins = [m.group(1) for m in (re.match(r"^pip==([0-9][0-9a-z.]*)\s+--hash=", ln) for ln in lines) if m]
    if len(lines) != 1 or len(pins) != 1:
        raise InstallError(f"{pip_lock.name} must pin pip alone, by version and hash")
    return pins[0]


def pin_pip(python: str, wheelhouse: Path, pip_lock: Path | None) -> None:
    """Replace a new venv's bundled pip with the hash-verified one, then prove the swap."""
    if pip_lock is None:
        return
    version = pip_version(pip_lock)
    # --force-reinstall makes pip fetch and hash-check the wheel even when the
    # bundled pip already reports the same version.
    _run(install_command(python, wheelhouse, [pip_lock]) + ["--force-reinstall"])
    r = subprocess.run([python, "-m", "pip", "--version"], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.startswith(f"pip {version} "):
        raise InstallError(f"venv pip is not {version} after the pinned install: {r.stdout.strip() or r.returncode}")


def check_expected(sha: str, expected: str | None) -> None:
    if expected is not None and sha != expected:
        raise InstallError(f"built {sha}, expected {expected}. The wheel differs from the other machine's build")


def _run(cmd: list[str]) -> None:
    # A child's stdout goes to fd 2, so this script's stdout carries only its own
    # result lines. The CI job and the Jetson read build's "<sha256>  <wheel>" line
    # from stdout, and pip's own progress there made that line unreadable. fd 2
    # rather than sys.stderr, because a replaced sys.stderr need not have a fileno.
    r = subprocess.run(cmd, stdout=2)
    if r.returncode != 0:
        raise InstallError(f"{' '.join(cmd[1:4])} failed with exit {r.returncode}")


def _venv_python(venv_dir: Path) -> str:
    return str(venv_dir / "bin" / "python")


def cmd_download(args) -> None:
    check_python(sys.version_info)
    args.wheelhouse.mkdir(parents=True, exist_ok=True)
    if args.pip_lock is not None:
        pip_version(args.pip_lock)
    _run(download_command(sys.executable, args.wheelhouse, args.pip_lock))


def cmd_build(args) -> None:
    check_python(sys.version_info)
    with tempfile.TemporaryDirectory() as tmp:
        build_venv = Path(tmp) / "build"
        _run([sys.executable, "-m", "venv", str(build_venv)])
        python = _venv_python(build_venv)
        pin_pip(python, args.wheelhouse, args.pip_lock)
        _run(install_command(python, args.wheelhouse, [BUILD]))
        r = subprocess.run([python, str(ROOT / "scripts" / "build_wheel.py"), "--out", str(args.out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise InstallError(r.stderr.strip() or "build_wheel failed")
        sha, name = r.stdout.split()
    print(f"{sha}  {name}")
    check_expected(sha, args.expect_sha256)


def cmd_install(args) -> None:
    check_python(sys.version_info)
    if args.venv.exists():
        raise InstallError(f"{args.venv.name} already exists. Install into a new directory")
    if not args.wheel.is_file():
        raise InstallError(f"no wheel at {args.wheel.name}")
    reference = direct_reference(args.wheel)
    _run([sys.executable, "-m", "venv", str(args.venv)])
    python = _venv_python(args.venv)
    pin_pip(python, args.wheelhouse, args.pip_lock)
    locks = [CORE, EMIT] if args.emit else [CORE]
    with tempfile.TemporaryDirectory() as tmp:
        ref_file = Path(tmp) / "cxbom-wheel.txt"
        ref_file.write_text(reference, encoding="utf-8")
        _run(install_command(python, args.wheelhouse, locks + [ref_file]))
    _run([python, str(ROOT / "scripts" / "verify_env.py")] + (["--emit"] if args.emit else []))
    print(f"install_cxbom: installed cxbom into {args.venv.name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="install_cxbom.py", description="Hash-locked, offline cxbom install.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("download", help="fetch the locked files (network)")
    d.add_argument("--wheelhouse", required=True, type=Path)
    b = sub.add_parser("build", help="build the wheel offline")
    b.add_argument("--wheelhouse", required=True, type=Path)
    b.add_argument("--out", required=True, type=Path)
    b.add_argument("--expect-sha256")
    i = sub.add_parser("install", help="install offline into a new venv")
    i.add_argument("--wheelhouse", required=True, type=Path)
    i.add_argument("--wheel", required=True, type=Path)
    i.add_argument("--venv", required=True, type=Path)
    i.add_argument("--emit", action="store_true", help="also install the emit lock (tokenizers)")
    for sp in (d, b, i):
        sp.add_argument("--pip-lock", type=Path, help="hash lock of the pip every step must run on")
    args = parser.parse_args(argv)
    try:
        {"download": cmd_download, "build": cmd_build, "install": cmd_install}[args.cmd](args)
    except InstallError as e:
        print(f"install_cxbom: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
