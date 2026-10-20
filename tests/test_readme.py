"""The README's commands parse, its installs are hash-locked, and its venv rule holds (Plan 4).

Owner: ATACE Working Group. Needs Plan 2 (cxbom.cli, cxbom.launch).
"""
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
# One derivation of the commands the spec documents and this slice does not
# ship, two consumers: the spec-wording guards and the README's ban list below.
# It lives in claim_helpers with the oracles it is built from, because a test
# module importing another test module for a shared derivation is the shape that
# file exists to remove.
from claim_helpers import next_plan_commands  # noqa: E402

from cxbom import cli, launch, launchpolicy  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def flat(text: str) -> str:
    return " ".join(text.replace("`", "").split())


def not_covered_rows() -> list[str]:
    """Top-level bullets of cli.NOT_COVERED, the text cxbom --help prints."""
    return [line.strip() for line in cli.NOT_COVERED.splitlines()[1:]
            if line.startswith("  ") and not line.startswith("      ")]


def spec_not_covered_channels() -> list[str]:
    """First-cell text of every row in tool.md section 2's "Not covered" table.

    Same parse tests/test_cli.py's test_help_lists_every_not_covered_row_from_the_spec
    uses to keep cxbom --help in step with the spec doc, reused here so the README
    is checked against that same ground truth instead of a row count copied once
    from a plan draft.
    """
    text = (ROOT / "docs" / "design" / "tool.md").read_text(encoding="utf-8")
    marker = text.index("Not covered in this version.")
    start = text.index("| Channel | Instead |", marker)
    lines = text[start:].splitlines()
    channels = []
    for line in lines[2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        channels.append(cells[0].replace("`", ""))
    return channels


def readme_commands() -> list[list[str]]:
    commands = []
    for block in re.findall(r"^```[a-z]*\n(.*?)^```", README, re.M | re.S):
        for line in block.replace("\\\n", " ").splitlines():
            if line.strip().startswith("cxbom "):
                commands.append(shlex.split(line.strip())[1:])
    return commands


def test_the_readme_lists_every_not_covered_row():
    rows = not_covered_rows()
    channels = spec_not_covered_channels()
    # cxbom --help (cli.NOT_COVERED) and tool.md section 2's table must name the
    # same channels, in the same order, or the two ground truths have drifted
    # apart and the README could match only one of them.
    assert [flat(r) for r in rows] == [flat(c) for c in channels]
    assert len(rows) >= 10, "the parse found suspiciously few not-covered rows"
    text = flat(README)
    for row in rows:
        assert flat(row) in text, row


def test_every_cxbom_command_in_the_readme_parses():
    commands = readme_commands()
    assert {c[0] for c in commands} >= {"keygen", "trust", "init", "approve", "proxy"}
    for argv in commands:
        head, _server_command = cli.split_command(argv)
        cli._parser().parse_args(head)


def readme_uvx_argvs() -> list[list[str]]:
    """Every uvx argv in the README, sliced from "uvx" to the end of the
    command: the two approve lines, the proxy line under Use (all three shell
    commands), and the mcp.json config block's "args" array."""
    argvs = []
    for block in re.findall(r"^```[a-z]*\n(.*?)^```", README, re.M | re.S):
        stripped = block.strip()
        if stripped.startswith("{"):
            data = json.loads(stripped)
            for server in data.get("mcpServers", {}).values():
                args = server.get("args", [])
                if "uvx" in args:
                    argvs.append(args[args.index("uvx"):])
            continue
        for line in block.replace("\\\n", " ").splitlines():
            tokens = shlex.split(line.strip())
            if "uvx" in tokens:
                argvs.append(tokens[tokens.index("uvx"):])
    return argvs


def test_every_readme_uvx_invocation_pins_mcp_exactly():
    """mcp-server-fetch==2025.4.7 declares mcp>=1.1.3 with no upper bound, so
    an unpinned "uvx mcp-server-fetch==2025.4.7" resolves whatever mcp PyPI
    carries the day someone runs it. mcp 2.0.0a1 renamed McpError with no
    compatibility alias, which breaks the import; 1.30.0 is the last release
    that still carries the name this server imports.

    cxbom's own launch policy does not require a --with pin (only that one,
    if given, is exact), so a bare "uvx mcp-server-fetch==2025.4.7" still
    passes package_version_problem. That means only an explicit check here,
    not the parser, catches a silent regression to the unpinned form.
    """
    argvs = readme_uvx_argvs()
    assert len(argvs) >= 4, "expected the two approve lines, the proxy line, and the mcp.json block"
    for argv in argvs:
        assert argv[0] == "uvx"
        assert launchpolicy.package_version_problem(argv) is None, argv
        assert "--with" in argv, f"no --with pin in {argv}"
        pin = argv[argv.index("--with") + 1]
        name, sep, _version = pin.partition("==")
        assert sep and name == "mcp" and launchpolicy._pip_exact(pin), pin


def test_every_install_in_the_readme_is_hash_locked():
    installs = [line for line in README.splitlines() if "pip install" in line]
    assert installs
    for line in installs:
        assert "--no-deps" in line and "--require-hashes" in line, line
    # The next-plan half is derived, not typed: the hardcoded list banned
    # "cxbom scan" and "cxbom gate" but not "cxbom guard", so a README line
    # saying guard detects something read as available and passed. Every
    # command section 11 documents and the parser does not ship is banned by
    # the same rule, and a command added to the spec is covered the same day.
    banned = ["curl", "@latest", "npx -y", "--fail-on inversion", "--first-party", "--rebind-binary"]
    banned += [f"cxbom {command}" for command in next_plan_commands()]
    for text in banned:
        assert text not in README, text


def readme_not_covered_rows() -> list:
    """Both cells of every row in the README's "Not covered" table."""
    start = README.index("| Channel | Instead |")
    rows = []
    for line in README[start:].splitlines()[2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip().replace("`", "") for c in line.strip().strip("|").split("|")]
        rows.append((cells[0], cells[1]))
    return rows


def help_not_covered_rows() -> list:
    """Both cells of every row cli.NOT_COVERED prints, the text cxbom --help shows."""
    rows = []
    for line in cli.NOT_COVERED.splitlines()[1:]:
        if line.startswith("      "):
            rows[-1][1].append(line.strip())
        elif line.startswith("  "):
            rows.append([line.strip(), []])
    return [(channel, " ".join(reason)) for channel, reason in rows]


def test_the_readme_table_repeats_the_help_text_row_for_row():
    """The README says "cxbom --help prints the same list", so both cells must match.

    test_the_readme_lists_every_not_covered_row above compares channels only,
    which let the wrapper row's reason differ between the README and --help
    while both tests stayed green.
    """
    rows = readme_not_covered_rows()
    assert len(rows) >= 10, "the README table parse found suspiciously few rows"
    assert rows == help_not_covered_rows()


def spec_lock_example_argv() -> list:
    """The argv of the C3 lock example in tool.md section 6."""
    text = (ROOT / "docs" / "design" / "tool.md").read_text(encoding="utf-8")
    block = re.search(r"^## 6\. .*?^```json\n(.*?)^```", text, re.M | re.S)
    assert block, "section 6 has no JSON lock example"
    return json.loads(block.group(1))["servers"]["fetch"]["envelope"]["entry"]["argv"]


def test_the_spec_lock_example_shows_the_pinned_fetch_argv():
    """tool.md's lock example holds the argv the README tells an operator to approve.

    A lock entry records the argv the proxy will enforce. Without the --with
    pin the example shows a launch that resolves whatever mcp PyPI carries that
    day, which is the failure the README's four sites fix.
    """
    argv = spec_lock_example_argv()
    assert argv in readme_uvx_argvs(), argv
    assert launchpolicy.package_version_problem(argv) is None, argv
    pin = argv[argv.index("--with") + 1]
    assert pin.startswith("mcp==") and launchpolicy._pip_exact(pin), pin


def _venv_tree(tmp_path: Path, copies: bool) -> Path:
    lock_dir = tmp_path / "proj"
    tree = lock_dir / "notes-server"
    tree.mkdir(parents=True)
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", *(["--copies"] if copies else []),
                    str(tree / ".venv")], check=True, capture_output=True)
    return lock_dir


def test_a_symlinked_venv_interpreter_is_refused(tmp_path):
    lock_dir = _venv_tree(tmp_path, copies=False)
    with pytest.raises(launch.LaunchError, match="put the binary on the standard PATH or pin its tree"):
        launch.resolve_argv0("notes-server/.venv/bin/python", lock_dir, ["notes-server"])


def test_a_copies_venv_interpreter_is_accepted(tmp_path):
    lock_dir = _venv_tree(tmp_path, copies=True)
    found = launch.resolve_argv0("notes-server/.venv/bin/python", lock_dir, ["notes-server"])
    assert Path(found).resolve().is_relative_to((lock_dir / "notes-server").resolve())
