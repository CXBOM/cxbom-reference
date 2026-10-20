"""cxbom approve with --accept: validation, per-era pins, signing (spec 7). Owner: ATACE Working Group."""
import io
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_mcp_server as fake  # noqa: E402
from proxy_helpers import (ACCEPT_FETCH, EMPTY_INSTRUCTIONS_SHA, FETCH_SHA, PASS, approve, project,  # noqa: E402
                           read_entry)

from cxbom import approve as approve_mod  # noqa: E402
from cxbom import launchpolicy, lockfile, paths, signing  # noqa: E402
from cxbom.canonical import instructions_sha256, tool_sha256  # noqa: E402
from cxbom.store import Store  # noqa: E402

HOME = str(paths.pw_dir())
OTHER = dict(fake.FETCH, name="other", description="Other tool.")


def trusted(setup):
    return signing.load_trusted(setup.config)


def refused(problem):
    """The runner refusal, which quotes the offending argument after the fixed text."""
    return problem is not None and problem.startswith("pin an exact package version: ")


def test_accept_pins_signs_and_stores(tmp_path):
    setup = project(tmp_path)
    code, out = approve(setup)
    assert code == 0, out
    env = read_entry(setup)
    assert env["entrySeq"] == 1 and env["notAfter"] is None
    entry = env["entry"]
    assert entry["allowAcceptFlag"] is True and entry["allowObserve"] is False
    legacy = entry["eras"]["legacy"]
    assert legacy["negotiatedVersion"] == "2025-11-25"
    assert legacy["instructionsSha256"] == EMPTY_INSTRUCTIONS_SHA
    pin = legacy["tools"]["fetch"]
    assert (pin["sha256"], pin["approvalMode"], pin["approvedBy"]) == (FETCH_SHA, "accept-flag", "demo-operator")
    lock = lockfile.read_lock(setup.lock_dir / "cxbom.lock")
    ve = lockfile.verified_entry(lock, "fetch", trusted(setup), setup.state,
                                 datetime.now(timezone.utc), update_highwater=False)
    assert ve.entry_seq == 1
    assert Store(setup.state / "store").get_json(tool_sha256(fake.FETCH)) == fake.FETCH
    assert "allowAcceptFlag: False -> True" in out and approve_mod.WARNING in out


def test_unaccepted_tool_is_left_unpinned(tmp_path):
    setup = project(tmp_path, script={"tools": [fake.FETCH, OTHER]})
    code, out = approve(setup)
    assert code == 0
    assert f"tool other {tool_sha256(OTHER)} left unpinned" in out
    assert set(read_entry(setup)["entry"]["eras"]["legacy"]["tools"]) == {"fetch"}


def test_unaccepted_instructions_sign_nothing(tmp_path):
    setup = project(tmp_path, script={"instructions": "Use fetch for web pages."})
    code, out = approve(setup, accept={FETCH_SHA: "reviewed"})
    assert code == 1
    assert f"--accept {instructions_sha256('Use fetch for web pages.')}" in out
    assert json.loads((setup.lock_dir / "cxbom.lock").read_text())["servers"] == {}


def test_accept_that_matches_nothing_is_refused(tmp_path):
    setup = project(tmp_path)
    code, out = approve(setup, accept=dict(ACCEPT_FETCH, **{"e" * 64: "typo"}))
    assert code == 2 and "matches no listed item" in out


def test_confirmation_mismatch_signs_nothing(tmp_path):
    setup = project(tmp_path)
    code, out = approve(setup, confirm="fetc")
    assert code == 1 and "Nothing was signed" in out
    assert json.loads((setup.lock_dir / "cxbom.lock").read_text())["servers"] == {}


def test_wrong_passphrase_is_refused(tmp_path):
    setup = project(tmp_path)
    code, out = approve(setup, passphrase=b"wrong")
    assert code == 2 and "could not decrypt" in out


@pytest.mark.parametrize("arg, kind", [
    (f"{HOME}/servers/fetch", "a home path"),
    ("/home/someone/x", "a home path"),
    ("~/x", "a home path"),
    ("https://user:pw@example.org/simple", "URL userinfo"),
    ("--host=10.0.0.12", "an IP literal"),
    ("--host=[fe80::1]", "an IP literal"),
    ("--registry=build-7.corp", "a hostname"),
    ("laptop.local", "a hostname"),
    ("--key=sk-abc", "a credential prefix"),
    ("Authorization: Bearer abc", "an Authorization header"),
    ("--token=q8ZfT2vLx9R4bN7mK3pW6sY1", "a high-entropy token"),
])
def test_identifying_argv_is_refused(arg, kind):
    assert approve_mod.identifying_content(arg, HOME) == kind


@pytest.mark.parametrize("arg", ["mcp-server-fetch==0.0.0", "https://pypi.org/simple", "fake_mcp_server.py",
                                 "@modelcontextprotocol/server-everything@2025.9.1",
                                 "img@sha256:" + "ab" * 32])
def test_ordinary_argv_is_accepted(arg):
    assert approve_mod.identifying_content(arg, HOME) is None


def test_identifying_pinned_env_value_is_refused(tmp_path):
    setup = project(tmp_path)
    code, out = approve(setup, env={"UV_INDEX_URL": "https://mirror.corp/simple"}, pin_env=["UV_INDEX_URL"])
    assert code == 2 and "--pin-env UV_INDEX_URL contains a hostname" in out
    code, out = approve(setup, env={"UV_INDEX_URL": "https://pypi.org/simple"}, pin_env=["UV_INDEX_URL"])
    assert code == 0, out


# --- Task 14b: reserved example names (RFC 2606, RFC 6761) are not hostnames ---


@pytest.mark.parametrize("value", ["inbox.test", "x.example", "a.invalid", "foo.localhost", "example.com",
                                   "INBOX.TEST", "Example.COM"])
def test_reserved_example_names_are_accepted(value):
    assert approve_mod.identifying_content(value, HOME) is None


@pytest.mark.parametrize("value, kind", [
    # A real hostname that merely contains "test" or "example" as one label,
    # not as its reserved TLD or domain, still refuses. test.evil.com's own
    # TLD is .com, and example.com.evil.net's own TLD is .net.
    ("test.evil.com", "a hostname"),
    ("example.com.evil.net", "a hostname"),
    # example.co is not one of the three reserved example.{com,net,org}
    # domains, so the exemption must not widen to "example." plus any TLD.
    ("example.co", "a hostname"),
    # Fix round 1, reviewer finding: a TLD-shaped allowlist entry for test,
    # example, invalid, or localhost let a real hostname through, because
    # _HOSTNAME's alternation matches greedily from the shortest suffix that
    # fits it: evil.com.test matched as one name ending in .test and would
    # have been exempted whole, when the real, identifying hostname inside
    # it is evil.com. The fix keeps only the exact example.com/net/org
    # allowlist, never a TLD pattern, so each of these is still refused as
    # the ordinary hostname (evil.com, x.local, acme.corp, api.acme.com)
    # that _HOSTNAME finds inside it.
    ("evil.com.test", "a hostname"),
    ("x.local.test", "a hostname"),
    ("acme.corp.invalid", "a hostname"),
    ("api.acme.com.localhost", "a hostname"),
    ("127.0.0.1", "an IP literal"),
])
def test_reserved_example_lookalikes_still_refused(value, kind):
    assert approve_mod.identifying_content(value, HOME) == kind


def test_reserved_example_name_accepted_in_pinned_env(tmp_path):
    setup = project(tmp_path)
    code, out = approve(setup, env={"UV_INDEX_URL": "https://inbox.test/simple"}, pin_env=["UV_INDEX_URL"])
    assert code == 0, out


def test_bad_role_is_refused(tmp_path):
    setup = project(tmp_path)
    out = io.StringIO()
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="op<script>", command=setup.argv)
    assert approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                           config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir) == 2
    assert "--approver" in out.getvalue()


def test_reapprove_keeps_unchanged_pins_and_bumps_the_sequence(tmp_path):
    setup = project(tmp_path)
    assert approve(setup)[0] == 0
    first = read_entry(setup)["entry"]["eras"]["legacy"]["tools"]["fetch"]
    code, out = approve(setup, accept={})
    assert code == 0, out
    env = read_entry(setup)
    assert env["entrySeq"] == 2 and env["entry"]["eras"]["legacy"]["tools"]["fetch"] == first
    assert "tool fetch" in out and "unchanged" in out


def test_changed_tool_needs_a_new_accept(tmp_path):
    setup = project(tmp_path)
    assert approve(setup)[0] == 0
    changed = dict(fake.FETCH, description="changed")
    (setup.lock_dir / "script.json").write_text(json.dumps({"tools": [changed]}))
    code, out = approve(setup, accept={})
    assert code == 0 and "left unpinned" in out
    assert read_entry(setup)["entry"]["eras"]["legacy"]["tools"] == {}


def test_era_both_pins_each_era(tmp_path):
    setup = project(tmp_path, script={"eras": ["legacy", "modern"]})
    code, out = approve(setup, era="both")
    assert code == 0, out
    assert set(read_entry(setup)["entry"]["eras"]) == {"legacy", "2026-07-28"}


def test_probe_picks_modern_for_a_modern_server(tmp_path):
    setup = project(tmp_path, script={"eras": ["modern"]})
    code, out = approve(setup)
    assert code == 0, out
    assert set(read_entry(setup)["entry"]["eras"]) == {"2026-07-28"}


def test_ambiguous_probe_needs_era(tmp_path):
    setup = project(tmp_path, script={"silent": ["server/discover"]})
    code, out = approve(setup, startup_timeout=0.5)
    assert code == 2 and "Pass --era" in out


def test_observe_entry_needs_no_not_after_and_never_expires(tmp_path):
    # Owner decision 2026-10-05: an observe entry has no tool-set lifetime.
    setup = project(tmp_path)
    code, out = approve(setup, allow_observe=True)
    assert code == 0, out
    env = read_entry(setup)
    assert env["entry"]["allowObserve"] is True and env["notAfter"] is None
    far = datetime.now(timezone.utc) + timedelta(days=3650)
    lock = lockfile.read_lock(setup.lock_dir / "cxbom.lock")
    ve = lockfile.verified_entry(lock, "fetch", trusted(setup), setup.state, far, update_highwater=False)
    assert ve.entry["allowObserve"] is True


@pytest.mark.parametrize("ahead", [timedelta(hours=12), timedelta(hours=30), timedelta(days=3650)])
def test_observe_not_after_has_no_maximum(tmp_path, ahead):
    setup = project(tmp_path)
    when = (datetime.now(timezone.utc) + ahead).strftime("%Y-%m-%dT%H:%M:%SZ")
    code, out = approve(setup, allow_observe=True, not_after=when)
    assert code == 0, out
    env = read_entry(setup)
    assert env["entry"]["allowObserve"] is True and env["notAfter"] == when


def test_not_after_must_be_future_utc_rfc3339(tmp_path):
    setup = project(tmp_path)
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    code, out = approve(setup, allow_observe=True, not_after=past)
    assert code == 2 and "must be in the future" in out
    code, out = approve(setup, allow_observe=True, not_after="2099-01-01T00:00:00+00:00")
    assert code == 2 and "with a Z suffix" in out
    code, out = approve(setup, allow_observe=True, not_after="tomorrow")
    assert code == 2 and "RFC 3339" in out
    assert "fetch" not in lockfile.read_lock(setup.lock_dir / "cxbom.lock")["servers"]


def test_duplicate_and_nonprintable_items_cannot_be_approved(tmp_path):
    setup = project(tmp_path, script={"tools": [fake.FETCH, fake.FETCH]})
    code, out = approve(setup)
    assert code == 2 and "more than once" in out
    sneaky = dict(fake.FETCH, description="Fetch\u202eevil")
    setup2 = project(tmp_path / "b", script={"tools": [sneaky]})
    code, out = approve(setup2, accept={tool_sha256(sneaky): "x", EMPTY_INSTRUCTIONS_SHA: "none"})
    assert code == 2 and "nonprintable" in out


def test_review_text_escapes_and_counts():
    shown, bad = approve_mod.review_text({"description": "a\u200bb\nc"})
    assert "\\u{200B}" in shown and bad == 1


def test_an_existing_entry_that_does_not_verify_is_not_extended(tmp_path):
    setup = project(tmp_path)
    assert approve(setup)[0] == 0
    lock_path = setup.lock_dir / "cxbom.lock"
    doc = json.loads(lock_path.read_text())
    doc["servers"]["fetch"]["envelope"]["entry"]["allowSampling"] = True
    lock_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    code, out = approve(setup, accept={})
    assert code == 2 and "does not verify" in out


def test_no_lock_means_run_init(tmp_path):
    setup = project(tmp_path)
    (setup.lock_dir / "cxbom.lock").unlink()
    code, out = approve(setup)
    assert code == 2 and "cxbom init" in out


# ----- tool names carrying control characters (hardening: terminal injection) -----------

def test_tool_name_with_control_characters_is_refused(tmp_path):
    sneaky = dict(fake.FETCH, name="fetch\x1b[31mFAKE")
    setup = project(tmp_path, script={"tools": [sneaky]})
    code, out = approve(setup, accept={})
    assert code == 2 and "usable name" in out
    assert "\x1b" not in out


def test_tool_name_empty_is_refused(tmp_path):
    setup = project(tmp_path, script={"tools": [dict(fake.FETCH, name="")]})
    code, out = approve(setup, accept={})
    assert code == 2 and "usable name" in out


# ----- package launcher exact version pin (owner ruling, docs/design/tool.md) -----------

@pytest.mark.parametrize("argv", [
    ["uvx", "mcp-server-fetch"],
    ["uvx", "mcp-server-fetch>=1.0"],
    ["uvx", "mcp-server-fetch@latest"],
    ["uvx", "--from", "mcp-server-fetch", "fetch-cli"],
    ["uvx", "--from=mcp-server-fetch>=1.0", "fetch-cli"],
    ["npx", "mcp-server-fetch"],
    ["npx", "-y", "mcp-server-fetch"],
    ["npx", "mcp-server-fetch@^1.2.3"],
    ["npx", "mcp-server-fetch@~1.2"],
    ["npx", "mcp-server-fetch@1.x"],
    ["npx", "mcp-server-fetch@>=1"],
    ["npx", "mcp-server-fetch@next"],
    ["npx", "mcp-server-fetch@latest"],
    ["npx", "@scope/pkg"],
    ["/usr/local/bin/npx", "mcp-server-fetch"],
    ["pipx", "run", "mcp-server-fetch"],
    ["pipx", "run", "--spec", "mcp-server-fetch", "fetch-cli"],
    ["pipx", "run", "--spec=mcp-server-fetch>=1.0", "fetch-cli"],
])
def test_package_launcher_without_exact_version_is_refused(argv):
    assert refused(launchpolicy.package_version_problem(argv))


@pytest.mark.parametrize("argv", [
    ["uvx", "mcp-server-fetch==0.0.0"],
    ["uvx", "--from", "mcp-server-fetch==0.0.0", "fetch-cli"],
    ["uvx", "--from=mcp-server-fetch==0.0.0", "fetch-cli"],
    ["npx", "mcp-server-fetch@2025.9.1"],
    ["npx", "-y", "mcp-server-fetch@2025.9.1"],
    ["npx", "@scope/pkg@1.2.3"],
    ["npx", "@modelcontextprotocol/server-everything@2025.9.1"],
    ["/usr/local/bin/npx", "mcp-server-fetch@1.2.3"],
    ["pipx", "run", "--spec", "mcp-server-fetch==0.0.0", "fetch-cli"],
    ["pipx", "run", "--spec=mcp-server-fetch==0.0.0", "fetch-cli"],
    ["pipx", "install", "mcp-server-fetch"],
])
def test_package_launcher_with_exact_version_is_accepted(argv):
    assert launchpolicy.package_version_problem(argv) is None


def test_run_refuses_unpinned_package_launcher_before_launching(tmp_path):
    setup = project(tmp_path)
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator",
                                      command=["uvx", "mcp-server-fetch"])
    out = io.StringIO()
    code = approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                           config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir)
    assert code == 2
    assert "pin an exact package version" in out.getvalue()
    assert json.loads((setup.lock_dir / "cxbom.lock").read_text())["servers"] == {}


# ----- Fix round 1: allowlist grammar closes the flag-scanning bypasses ------------------

@pytest.mark.parametrize("argv", [
    # _flag_value used to scan past a decoy positional to find a pinned flag later.
    ["uvx", "evilpkg", "--from", "x==1.0"],
    ["pipx", "run", "evilpkg", "--spec", "x==1.0"],
    # _first_positional ignored --package=, repeated -p, and flag values.
    ["npx", "--package=evil", "bin@1.2.3"],
    ["npx", "-p", "a@1.0.0", "-p", "evil", "bin"],
    ["uvx", "--with", "x==1.0", "evilpkg"],
    # npm treats anything short of strict semver as a range or dist-tag.
    ["npx", "foo@1"],
    ["npx", "foo@1.2"],
    ["npx", "foo@1abc"],
    ["npx", "foo@1.0.0rc1"],
    # A case-sensitive match missed the launcher on a case-insensitive filesystem.
    ["NPX", "evilpkg"],
    ["Uvx", "evilpkg"],
    ["PIPX", "run", "evilpkg"],
    # Round 1 forms: an unlisted flag before the command/package, and pipx
    # global flags ahead of "run".
    ["npx", "--registry=https://example.com", "pkg@1.2.3"],
    ["uvx", "--refresh", "pkg==1.2.3"],
    ["pipx", "--verbose", "run", "pkg==1.2.3"],
    ["uv", "tool", "run", "evilpkg"],
    ["npm", "exec", "evilpkg"],
    ["npm", "exec", "--", "evilpkg"],
    # Fix round 2, finding B: npm's "x" alias for exec, a flag ahead of the
    # npm subcommand, npm init/create (no pinned form exists), and a flag
    # between "uv" and "tool" or "tool uvx" left unchecked.
    ["npm", "x", "evilpkg"],
    ["npm", "--yes", "exec", "evilpkg"],
    ["npm", "-y", "exec", "--", "evilpkg"],
    # A flag before the subcommand is refused even when the target after it
    # is otherwise a validly pinned spec: this grammar cannot tell what the
    # flag itself might change (a registry override, say).
    ["npm", "--registry=https://evil.example", "exec", "pkg@1.2.3"],
    ["uv", "--offline", "tool", "run", "pkg==1.0"],
    ["npm", "init", "evil"],
    ["npm", "create", "evil"],
    ["npm", "init"],
    ["uv", "--offline", "tool", "run", "evilpkg"],
    ["uv", "-q", "tool", "run", "evilpkg"],
    ["uv", "tool", "uvx", "evilpkg"],
    # Fix round 2, finding C: a URL, a git/file reference, or a bare "@"
    # riding along after what looks like a well-formed version suffix.
    ["npx", "https://evil.example/x.tgz@1.2.3"],
    ["npx", "-p", "https://evil.example/x.tgz@1.2.3", "bin"],
    ["npx", "github:evil/repo@1.2.3"],
    ["uvx", "evil@https://evil.example/e.whl==1.0"],
    ["uvx", "--from", "evil@https://evil.example/e.whl==1.0", "cmd"],
    ["uvx", "--from", "git+https://github.com/evil/repo==1.0", "cmd"],
    ["pipx", "run", "--spec", "evil@https://evil.example/e.whl==1.0", "app"],
    ["pipx", "run", "evil@https://evil.example/e.whl==1.0"],
])
def test_package_launcher_bypass_is_refused(argv):
    assert refused(launchpolicy.package_version_problem(argv))


@pytest.mark.parametrize("argv", [
    ["npx", "-y", "-p", "@scope/pkg@1.2.3", "bin"],
    ["uvx", "--python", "3.12", "pkg==1.0"],
    ["uvx", "--from", "pkg==1.0", "cmd"],
    ["uv", "tool", "run", "pkg==1.0"],
    ["uv", "tool", "uvx", "pkg==1.0"],
    ["npm", "exec", "--", "pkg@1.2.3"],
    ["npm", "exec", "-y", "pkg@1.2.3"],
    ["npm", "x", "-p", "@scope/pkg@1.2.3", "bin"],
    ["pipx", "run", "--spec", "pkg==1.0", "app"],
])
def test_package_launcher_allowlisted_form_is_accepted(argv):
    assert launchpolicy.package_version_problem(argv) is None


@pytest.mark.parametrize("argv0, refused_rest, accepted_rest", [
    ("npx-cli.js", ["evilpkg"], ["evilpkg@1.2.3"]),
    ("NPX-CLI.JS", ["evilpkg"], ["evilpkg@1.2.3"]),
    ("npm-cli.js", ["exec", "evilpkg"], ["exec", "evilpkg@1.2.3"]),
])
def test_launcher_alias_names_are_recognized(argv0, refused_rest, accepted_rest):
    """Homebrew, nvm, and a plain npm install all realpath npx/npm to a JS
    entry point rather than a file literally named npx/npm, so that
    basename must be recognized directly, with no filesystem needed since
    it can appear as argv0 itself (controller ruling 3)."""
    assert refused(launchpolicy.package_version_problem([argv0, *refused_rest]))
    assert launchpolicy.package_version_problem([argv0, *accepted_rest]) is None


def test_launcher_alias_path_form_resolves_through_symlink(tmp_path):
    """A path-form argv0 that is itself a symlink to the real npx-cli.js is
    still caught: this is the actual reviewer-confirmed bypass
    (["<dir>/n","evilpkg"] with n a real symlink to npx was accepted before
    this round), fixed by resolving argv0's own realpath directly rather
    than skipping path-form entirely. No writes outside tmp_path."""
    real = tmp_path / "npx-cli.js"
    real.write_text("#!/usr/bin/env node\n")
    link = tmp_path / "n"
    link.symlink_to(real)
    assert refused(launchpolicy.package_version_problem([str(link), "evilpkg"]))
    assert launchpolicy.package_version_problem([str(link), "evilpkg@1.2.3"]) is None


def test_launcher_alias_bare_name_resolves_through_symlink(tmp_path, monkeypatch):
    """The bare-name branch is exercised the same way. launch.resolve_argv0
    (the trusted-search-path lookup) is stubbed to point at the tmp_path
    fixture instead of touching a real trusted directory or HOME. The
    realpath-following and alias-mapping logic under test is otherwise
    identical to the path-form case above."""
    real = tmp_path / "npx-cli.js"
    real.write_text("#!/usr/bin/env node\n")
    link = tmp_path / "n"
    link.symlink_to(real)
    monkeypatch.setattr(approve_mod.launch, "resolve_argv0", lambda argv0, lock_dir, trees: str(link))
    assert refused(launchpolicy.package_version_problem(["n", "evilpkg"]))
    assert launchpolicy.package_version_problem(["n", "evilpkg@1.2.3"]) is None


def test_path_form_launcher_is_realpath_resolved_without_launch_resolve_argv0(tmp_path, monkeypatch):
    """A path-form launcher is resolved with a direct os.path.realpath, not
    through launch.resolve_argv0: that function's path-form branch also
    requires lock_dir and pin_trees for a tree-containment authorization
    check unrelated to identifying what the file is, and this pre-launch
    check has neither to give it. Authorization stays launch.check_launch's
    job at real launch time."""
    def boom(*a, **k):
        raise AssertionError("resolve_argv0 must not be called for a path-form argv0")
    monkeypatch.setattr(approve_mod.launch, "resolve_argv0", boom)
    real = tmp_path / "npx-cli.js"
    real.write_text("#!/usr/bin/env node\n")
    link = tmp_path / "n"
    link.symlink_to(real)
    assert launchpolicy.package_version_problem([str(link), "pkg@1.2.3"]) is None


# ----- Fix round 1: escaping every displayed server-controlled name ---------------------

def test_left_unpinned_tool_name_with_bidi_override_is_escaped(tmp_path):
    tricky = dict(fake.FETCH, name="fetch\u202eevil")
    setup = project(tmp_path, script={"tools": [tricky]})
    code, out = approve(setup, accept={EMPTY_INSTRUCTIONS_SHA: "no instructions"})
    assert code == 0, out
    assert "\u202e" not in out
    assert "\\u{202E}" in out


def test_left_unpinned_tool_name_with_c1_control_is_escaped(tmp_path):
    tricky = dict(fake.FETCH, name="fetch\x9bX")
    setup = project(tmp_path, script={"tools": [tricky]})
    code, out = approve(setup, accept={EMPTY_INSTRUCTIONS_SHA: "no instructions"})
    assert code == 0, out
    assert "\x9b" not in out
    assert "\\u{009B}" in out


def test_duplicate_name_error_escapes_the_name(tmp_path):
    tricky = dict(fake.FETCH, name="fetch\u202e")
    setup = project(tmp_path, script={"tools": [tricky, dict(tricky)]})
    code, out = approve(setup, accept={})
    assert code == 2 and "more than once" in out
    assert "\u202e" not in out
    assert "\\u{202E}" in out


def test_uncanonicalizable_tool_name_error_escapes_the_name(tmp_path):
    huge = dict(fake.FETCH, name="fetch\u202e", oversized=10 ** 60)
    setup = project(tmp_path, script={"tools": [huge]})
    code, out = approve(setup, accept={})
    assert code == 2 and "cannot be canonicalized" in out
    assert "\u202e" not in out
    assert "\\u{202E}" in out


# ----- Fix round 1: serverInfo sanitization (org.cxbom/* strip, size cap, identity) ------

def test_server_info_strips_forged_org_cxbom_keys(tmp_path):
    setup = project(tmp_path, script={"serverInfo": {"name": "fake-mcp", "org.cxbom/reviewed": True}})
    code, out = approve(setup)
    assert code == 0, out
    assert "org.cxbom" not in json.dumps(read_entry(setup))


def test_server_info_strips_org_cxbom_keys_at_every_depth(tmp_path):
    """A top-level-only strip would still publish a forged key nested inside
    a sub-object of serverInfo (fix round 2, controller ruling D)."""
    setup = project(tmp_path, script={"serverInfo": {
        "name": "fake-mcp",
        "nested": {"org.cxbom/evil": 1, "keep": True},
        "list": [{"org.cxbom/also-evil": 2, "keep": True}],
    }})
    code, out = approve(setup)
    assert code == 0, out
    env = read_entry(setup)
    assert "org.cxbom" not in json.dumps(env)
    server_info = env["entry"]["eras"]["legacy"]["serverInfo"]
    assert server_info["nested"] == {"keep": True}
    assert server_info["list"] == [{"keep": True}]


def test_server_info_over_size_cap_is_refused(tmp_path):
    setup = project(tmp_path, script={"serverInfo": {"name": "x" * (approve_mod.SERVER_INFO_MAX_BYTES + 1)}})
    code, out = approve(setup)
    assert code == 2 and "cannot be pinned" in out
    assert json.loads((setup.lock_dir / "cxbom.lock").read_text())["servers"] == {}


def test_server_info_identifying_content_is_refused(tmp_path):
    setup = project(tmp_path, script={"serverInfo": {"name": "fake-mcp", "host": "build-7.corp"}})
    code, out = approve(setup)
    assert code == 2 and "serverInfo contains" in out and "a hostname" in out


# ----- Task 12b: every registry runner in the spec 6 table (fix round 3) -----------------

DIGEST = "sha256:" + "0123456789abcdef" * 4


@pytest.mark.parametrize("argv", [
    # Carried-in finding: a global flag's separate value was taken as the
    # subcommand, so the scan never reached the real one.
    ["npm", "--prefix", "/tmp", "exec", "evilpkg"],
    ["npm", "-C", "/tmp", "exec", "evilpkg"],
    ["npm", "--registry", "https://evil.example", "x", "evilpkg"],
    ["npm", "--yes", "true", "exec", "evilpkg"],
    ["npm", "--prefix", "x", "exec", "pkg@1.2.3"],
    ["uv", "--directory", "/tmp", "tool", "run", "evilpkg"],
    ["uv", "--directory", "d", "tool", "run", "pkg==1.0"],
    ["uv", "--color", "never", "tool", "uvx", "evilpkg"],
    ["uv", "tool", "-q", "run", "evilpkg"],
    ["uv", "tool", "--offline", "run", "pkg==1.0"],
    ["uv", "tool", "--directory", "/tmp", "uvx", "evilpkg"],
    # npm abbreviations, aliases, and misspellings of exec, init, and create.
    ["npm", "exe", "evilpkg"],
    ["npm", "exe", "pkg@1.2.3"],
    ["npm", "innit", "evil"],
    ["npm", "ini", "evil"],
    ["npm", "cre", "evil"],
    ["npm", "creat", "evil"],
    # uv run fetches through --with, or a remote script by URL.
    ["uv", "run", "--with", "pkg"],
    ["uv", "run", "--with", "pkg>=1"],
    ["uv", "run", "--with=pkg==1.0,evil", "python"],
    ["uv", "run", "--with-requirements", "r.txt", "python"],
    ["uv", "run", "https://evil.example/s.py"],
    # bunx, bun x, pnpm dlx, yarn dlx, pnpx: unpinned, range, tag, latest,
    # URL/git/file specs, and any flag before the package.
    ["bunx", "pkg"],
    ["bunx", "--bun", "pkg@1.2.3"],
    ["bunx", "github:evil/repo@1.2.3"],
    ["bun", "x", "pkg@latest"],
    ["bun", "x", "pkg@next"],
    ["bun", "--silent", "x", "pkg@1.2.3"],
    ["bun", "create", "evil"],
    ["pnpm", "dlx", "pkg"],
    ["pnpm", "dlx", "pkg@~1.2"],
    ["pnpm", "dlx", "--package", "a@1.0.0", "--package", "evil", "bin"],
    ["pnpm", "dlx", "file:../evil@1.0.0"],
    ["pnpm", "dlx", "--silent", "pkg@1.2.3"],
    ["pnpm", "--silent", "dlx", "pkg@1.2.3"],
    ["pnpm", "create", "evil"],
    ["pnpx", "pkg"],
    ["yarn", "dlx", "pkg@^1"],
    ["yarn", "dlx", "https://evil.example/x.tgz@1.2.3"],
    ["yarn", "--silent", "dlx", "pkg@1.2.3"],
    ["yarn", "create", "evil"],
    # pipx run: every --spec pinned, and no other flag.
    ["pipx", "run", "--spec", "pkg==1.0", "--spec", "evil", "app"],
    ["pipx", "run", "--index-url", "https://evil.example", "pkg==1.0"],
    ["pipx", "-v", "run", "pkg==1.0"],
    # An interpreter counts as the runner it starts.
    ["python3", "-m", "pipx", "run", "pkg"],
    ["python3", "-m", "uv", "tool", "run", "pkg"],
    ["python3", "-m", "uvx", "pkg"],
    ["python3", "-mpipx", "run", "pkg"],
    ["python3", "-m", "pipx.__main__", "run", "pkg"],
    ["python3.12", "-m", "PIPX", "run", "pkg"],
    ["python3", "-I", "-m", "pipx", "run", "pkg==1.0"],
    ["python3", "-Im", "pipx", "run", "pkg==1.0"],
    ["python3", "-m", "pipx.main", "run", "pkg==1.0"],
    # A value flag's separate value may not be another flag.
    ["uvx", "--python", "--from", "pkg==1.0", "evil"],
    # A trailing newline passes a "$" anchor but not fullmatch.
    ["uvx", "pkg==1.0\n"],
    ["uvx", "pkg\n==1.0"],
    ["npx", "pkg@1.0.0\n"],
    ["npx", "pkg\n@1.0.0"],
    # docker and podman: no digest, a tag instead of a digest, a digest in the
    # wrong case or length, and flags misparsed without the arity table.
    ["docker", "run", "mcp/fetch"],
    ["docker", "run", "mcp/fetch:1.0"],
    ["docker", "run", "mcp/fetch@sha256:" + "0123456789ABCDEF" * 4],
    ["docker", "run", "mcp/fetch@sha256:" + "0" * 63],
    ["docker", "run", "@" + DIGEST],
    ["docker", "run", f"mcp/fetch@{DIGEST}\n"],
    ["docker", "run"],
    ["docker", "run", "--rm", "true", f"img@{DIGEST}"],
    ["docker", "run", "-ei", "KEY=v", f"img@{DIGEST}"],
    ["docker", "run", "--network", f"img@{DIGEST}"],
    ["docker", "run", "--", "--rm"],
    ["docker", "-H", "unix:///x.sock", "run", "mcp/fetch"],
    ["docker", "-c", "run", "run", "mcp/fetch:1.0"],
    ["docker", "container", "run", "mcp/fetch"],
    ["podman", "run", "mcp/fetch"],
    ["podman", "container", "run", "mcp/fetch:latest"],
])
def test_registry_runner_without_exact_pin_is_refused(argv):
    assert refused(launchpolicy.package_version_problem(argv))


@pytest.mark.parametrize("argv, flag", [
    (["docker", "run", "--unknown-flag", "x", f"img@{DIGEST}"], "--unknown-flag"),
    (["docker", "run", "-Z", f"img@{DIGEST}"], "-Z"),
    (["docker", "run", "-iZ", f"img@{DIGEST}"], "-Z"),
    (["docker", "run", "--rm=yes", f"img@{DIGEST}"], "--rm=yes"),
    (["docker", "run", "-i=1", f"img@{DIGEST}"], "-i=1"),
    (["docker", "--bogus", "run", f"img@{DIGEST}"], "--bogus"),
    (["docker", "container", "--rm", "run", f"img@{DIGEST}"], "--rm"),
    (["podman", "--remote", "run", f"img@{DIGEST}"], "--remote"),
    (["podman", "--log-level", "debug", "container", "run", f"img@{DIGEST}"], "--log-level"),
    (["docker", "run", "--rootfs", f"img@{DIGEST}"], "--rootfs"),
])
def test_container_flag_missing_from_the_table_is_refused_by_name(argv, flag):
    assert launchpolicy.package_version_problem(argv) == \
        f"unsupported container flag {flag}: the image cannot be located"


def test_podman_rootfs_is_refused():
    for argv in (["podman", "run", "--rootfs", "/x"], ["podman", "run", "--rootfs=true", "/x"]):
        assert launchpolicy.package_version_problem(argv) == "podman --rootfs runs a host path, not a pinned image"


@pytest.mark.parametrize("argv", [
    ["uv", "run", "script.py"],
    ["uv", "run", "--no-project", "--script", "server.py"],
    ["uv", "run", "--with", "pkg==1.0", "python", "x.py"],
    ["uv", "run", "--with=pkg==1.0", "--python", "3.12", "python", "x.py", "--with", "evil"],
    ["uv", "pip", "install", "anything"],
    ["uv", "tool", "install", "anything"],
    ["bunx", "pkg@1.2.3"],
    ["bun", "x", "@scope/pkg@1.2.3", "--anything"],
    ["bun", "server.ts"],
    ["pnpm", "dlx", "pkg@1.2.3"],
    ["pnpm", "dlx", "--package", "a@1.0.0", "--package=b@2.0.0", "bin"],
    ["pnpx", "pkg@1.2.3"],
    ["yarn", "dlx", "--package", "a@1.0.0", "bin"],
    ["npm", "run", "start"],
    ["pipx", "run", "pkg==1.0"],
    ["python3", "-m", "pipx", "run", "--spec", "pkg==1.0", "app"],
    ["python3", "-m", "uv", "tool", "run", "pkg==1.0"],
    ["docker", "run", "-i", "--rm", "-e", "KEY=v", "-v", "/data:/data", "--network", "none", f"mcp/fetch@{DIGEST}"],
    ["docker", "-c", "ctx", "run", "-it", f"img@{DIGEST}"],
    ["docker", "--context=ctx", "-D", "run", f"img@{DIGEST}"],
    ["docker", "run", "-eKEY=v", f"img@{DIGEST}", "--arg"],
    ["docker", "run", "-ie", "KEY=v", f"img@{DIGEST}", "--unknown-after-image"],
    ["docker", "container", "run", "--pull=never", f"img@{DIGEST}"],
    ["docker", "run", "--net", "none", "--rm=false", "-t=true", f"img@{DIGEST}"],
    ["docker", "run", "--", f"img@{DIGEST}"],
    ["docker", "run", f"registry.example:5000/team/img:1.0@{DIGEST}"],
    ["docker", "ps"],
    ["podman", "run", "--userns", "keep-id", f"img@{DIGEST}"],
    ["podman", "container", "run", "--rm", f"img@{DIGEST}"],
])
def test_registry_runner_with_exact_pin_is_accepted(argv):
    assert launchpolicy.package_version_problem(argv) is None


def test_refusal_quotes_the_offending_argument_escaped():
    assert launchpolicy.package_version_problem(["npx", "evil\x1b[2J"]) == \
        "pin an exact package version: evil\\u{001B}[2J"
    problem = launchpolicy.package_version_problem(["docker", "run", "--bogus=SECRETVALUE\x9b", "img"])
    assert problem == "unsupported container flag --bogus: the image cannot be located"


@pytest.mark.parametrize("script", ["npx-cli.js", "npm-cli.js"])
def test_node_running_the_npm_scripts_is_that_runner(tmp_path, script):
    stub = tmp_path / "lib" / script
    stub.parent.mkdir()
    stub.write_text("#!/usr/bin/env node\n")
    rest = ["exec"] if script == "npm-cli.js" else []
    assert refused(launchpolicy.package_version_problem(["node", str(stub), *rest, "evilpkg"]))
    assert launchpolicy.package_version_problem(["node", str(stub), *rest, "evilpkg@1.2.3"]) is None
    # A symlink under another name is matched by its realpath target.
    link = tmp_path / "tool.js"
    link.symlink_to(stub)
    assert refused(launchpolicy.package_version_problem(["node", str(link), *rest, "evilpkg"]))
    # A node option outside the allowlist is refused before the runner is
    # even reached, and an allowlisted one still may not precede a runner.
    assert launchpolicy.package_version_problem(["node", "--require", "./x.js", str(stub), *rest,
                                                "evilpkg@1.2.3"]) == "put the code in a pinned file"
    assert launchpolicy.package_version_problem(["node", "--inspect", str(stub), *rest, "evilpkg@1.2.3"]) == \
        "put the code in a pinned file"
    assert refused(launchpolicy.package_version_problem(["node", "--no-warnings", str(stub), *rest,
                                                        "evilpkg@1.2.3"]))


def test_python_running_a_pipx_script_is_pipx(tmp_path):
    stub = tmp_path / "pipx"
    stub.write_text("#!/usr/bin/env python3\n")
    assert refused(launchpolicy.package_version_problem(["python3", str(stub), "run", "evilpkg"]))
    assert launchpolicy.package_version_problem(["python3", str(stub), "run", "pkg==1.0"]) is None
    assert refused(launchpolicy.package_version_problem(["python3", "-u", str(stub), "run", "pkg==1.0"]))


def test_runner_matched_under_every_name_argv0_resolves_to(tmp_path):
    """A symlink named uvx whose target is uv is checked as uvx and as uv."""
    uv = tmp_path / "uv"
    uv.write_text("stub")
    link = tmp_path / "uvx"
    link.symlink_to(uv)
    assert refused(launchpolicy.package_version_problem([str(link), "tool", "run", "pkg==1.0"]))
    assert refused(launchpolicy.package_version_problem([str(link), "run", "--with", "evil", "x"]))


def test_container_flag_table_ships_with_the_package():
    table = launchpolicy._flag_table()
    assert {"_source", "docker", "podman", "docker_global"} <= set(table)
    assert "Docker 29.5.2" in table["_source"]["docker"] and "v5.6.1" in table["_source"]["podman"]
    assert table["docker"]["long"]["rm"] == "bool" and table["docker"]["short"]["e"] == "env"
    assert table["podman"]["long"]["rootfs"] == "bool"


def test_run_checks_identifying_content_before_quoting_the_argument(tmp_path):
    """The refusal quotes the offending argument, so a home path in it must be
    refused by the identifying-content check first and never echoed."""
    setup = project(tmp_path)
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator",
                                      command=["npx", HOME + "/evil"])
    out = io.StringIO()
    code = approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                           config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir)
    assert code == 2
    assert "argv contains a home path" in out.getvalue()
    assert "pin an exact package version" not in out.getvalue()


@pytest.mark.parametrize("field, value", [("server_id", "fetch\n"), ("approver", "demo-operator\n")])
def test_trailing_newline_in_ids_is_refused(tmp_path, field, value):
    setup = project(tmp_path)
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator", command=["python3", "x.py"])
    setattr(opts, field, value)
    out = io.StringIO()
    code = approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                           config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir)
    assert code == 2 and "must match" in out.getvalue()


# ----- Task 12b fix round 1 --------------------------------------------------------------

@pytest.mark.parametrize("argv", [
    # npm parses flags anywhere until "--", so a flag after the package applies.
    ["npm", "exec", "cowsay@1.0.0", "--package=evil"],
    ["npm", "x", "cowsay@1.0.0", "-p", "evil"],
    ["npm", "exec", "--package=cowsay@1.0.0", "cowsay", "--package=evil"],
    ["npm", "exec", "cowsay@1.0.0", "--registry=https://r.example"],
    ["npm", "exec", "-y", "cowsay@1.0.0", "--", "--help"],
    # npm's install family, by name, alias, and abbreviation.
    ["npm", "install"],
    ["npm", "install", "evil"],
    ["npm", "i", "evil"],
    ["npm", "add", "evil"],
    ["npm", "ci"],
    ["npm", "isntall", "evil"],
    ["npm", "instal", "evil"],
    ["npm", "install-test"],
    ["npm", "cit"],
    ["npm", "--silent", "install", "evil"],
    # corepack starts the package manager it names.
    ["corepack", "pnpm", "dlx", "evil"],
    ["corepack", "yarn", "dlx", "evil"],
    ["corepack", "npx", "evil"],
    ["corepack", "npm", "exec", "evil"],
    ["corepack", "pnpm@9.0.0", "dlx", "evil"],
    ["corepack", "--silent", "pnpm", "dlx", "pkg@1.2.3"],
    ["node", "/opt/homebrew/lib/node_modules/corepack/dist/corepack.js", "pnpm", "dlx", "evil"],
    ["/opt/homebrew/lib/node_modules/corepack/dist/corepack.js", "npx", "evil"],
    # Script-form runners known by where they sit.
    ["node", "/opt/homebrew/lib/node_modules/npm/index.js", "exec", "evil"],
    ["node", "/opt/homebrew/lib/node_modules/npm", "exec", "evil"],
    ["python3", "/opt/x/pipx.pyz", "run", "evil"],
    ["python3", "/opt/x/site-packages/pipx/__main__.py", "run", "evil"],
    ["python3", "/opt/x/site-packages/uv/__main__.py", "tool", "run", "evil"],
    ["python3", "/opt/x/site-packages/uvx/__main__.py", "evil"],
    # docker mcp and transport-prefixed images.
    ["docker", "mcp", "gateway", "run", "--servers=fetch"],
    ["docker", "-D", "mcp", "gateway", "run"],
    ["podman", "run", "oci-archive:/tmp/x@sha256:" + "a" * 64],
    ["podman", "run", "docker-archive:/tmp/x@sha256:" + "a" * 64],
    ["podman", "run", "dir:/tmp/x@sha256:" + "a" * 64],
    ["podman", "run", "containers-storage:x@sha256:" + "a" * 64],
    ["docker", "run", "docker-daemon:x@sha256:" + "a" * 64],
    ["podman", "run", "OCI:/tmp/x@sha256:" + "a" * 64],
])
def test_fix_round_1_bypass_is_refused(argv):
    assert refused(launchpolicy.package_version_problem(argv))


@pytest.mark.parametrize("argv", [
    ["npm", "exec", "--", "cowsay@1.0.0", "--help"],
    ["npm", "exec", "-y", "--", "cowsay@1.0.0", "--package=anything"],
    ["npx", "cowsay@1.0.0", "--package=anything"],
    ["corepack", "pnpm@9.1.0", "dlx", "pkg@1.2.3"],
    ["corepack", "yarn@4.2.2", "dlx", "--package", "a@1.0.0", "bin"],
    ["corepack", "enable"],
    ["docker", "run", "registry.example/oci:1@sha256:" + "a" * 64],
])
def test_fix_round_1_control_is_accepted(argv):
    assert launchpolicy.package_version_problem(argv) is None


def _script(tmp_path, body):
    (tmp_path / "script.py").write_text(body)
    return tmp_path


INLINE_OK = """# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "httpx==0.27.0",
#   'mcp[cli]==1.2.0',  # the server SDK
# ]
# ///
print(1)
"""


@pytest.mark.parametrize("argv", [["uv", "run", "script.py"], ["uv", "run", "--script", "script.py"]])
def test_uv_run_inline_exact_pins_are_accepted(tmp_path, argv):
    lock_dir = _script(tmp_path, INLINE_OK)
    assert launchpolicy.package_version_problem(argv, lock_dir) is None
    assert launchpolicy.package_version_problem(["uv", "run", str(lock_dir / "script.py")]) is None


@pytest.mark.parametrize("body", [
    '# /// script\n# dependencies = ["httpx"]\n# ///\n',
    '# /// script\n# dependencies = ["httpx>=0.27"]\n# ///\n',
    '# /// script\n# dependencies = [\n#   "httpx==0.27.0",\n#   "evil",\n# ]\n# ///\n',
    '# /// script\n# dependencies = ["git+https://e.example/r==1.0"]\n# ///\n',
    '# /// script\n# dependencies = ["httpx==0.27.0"]\n# [tool.uv]\n# index-url = "https://e.example"\n# ///\n',
    '# /// script\n# dependencies = ["a==1.0"]\n# dependencies = ["evil"]\n# ///\n',
    '# /// script\n# dependencies = ["a==1.0"]\n# dependencies = ["b==2.0"]\n# ///\n',
    '# /// script\n# dependencies = ["a\\u0020==1.0"]\n# ///\n',
    '# /// script\n# dependencies = """evil"""\n# ///\n',
    '# /// script\n#dependencies = ["evil"]\n# ///\n',
    '# /// script\n# dependencies = ["a==1.0"]\n',
    '# /// script\n# dependencies = ["a==1.0"]\n# ///\n# /// script\n# dependencies = ["evil"]\n# ///\n',
    '#  /// script\n# dependencies = ["evil"]\n# ///\n',
])
def test_uv_run_inline_unpinned_or_unparsed_is_refused(tmp_path, body):
    lock_dir = _script(tmp_path, body)
    assert refused(launchpolicy.package_version_problem(["uv", "run", "script.py"], lock_dir))
    assert refused(launchpolicy.package_version_problem(["uv", "run", "--script", "script.py"], lock_dir))


def test_uv_run_unreadable_target_is_refused(tmp_path):
    lock_dir = _script(tmp_path, INLINE_OK)
    (lock_dir / "script.py").write_bytes(b"\xff\xfe not utf-8")
    assert refused(launchpolicy.package_version_problem(["uv", "run", "script.py"], lock_dir))


def test_run_reads_inline_metadata_from_the_lock_directory(tmp_path):
    setup = project(tmp_path)
    (setup.lock_dir / "script.py").write_text('# /// script\n# dependencies = ["evil"]\n# ///\n')
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator",
                                      command=["uv", "run", "script.py"])
    out = io.StringIO()
    code = approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                           config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir)
    assert code == 2 and "pin an exact package version: evil" in out.getvalue()
    assert json.loads((setup.lock_dir / "cxbom.lock").read_text())["servers"] == {}


def test_relative_runner_script_resolves_against_the_lock_directory(tmp_path):
    real = tmp_path / "npx-cli.js"
    real.write_text("")
    (tmp_path / "tool.js").symlink_to(real)
    assert refused(launchpolicy.package_version_problem(["node", "tool.js", "evilpkg"], tmp_path))


def test_home_path_check_is_case_insensitive():
    assert approve_mod.identifying_content("/users/someone/x", "") == "a home path"
    assert approve_mod.identifying_content(HOME.upper() + "/x", HOME) == "a home path"
    # A home outside the /Users and /home patterns is matched through the
    # value itself, still case-insensitively.
    assert approve_mod.identifying_content("/VOLUMES/DATA/ME/x", "/Volumes/Data/Me") == "a home path"


# ----- Task 12b fix round 2 --------------------------------------------------------------

@pytest.mark.parametrize("argv", [
    # corepack resolves a bare name, a tag, or a range against the registry.
    ["corepack", "pnpm@latest", "dlx", "x@1.0.0"],
    ["corepack", "pnpm@9", "dlx", "x@1.0.0"],
    ["corepack", "pnpm@^9.1.0", "dlx", "x@1.0.0"],
    ["corepack", "pnpm", "dlx", "x@1.0.0"],
    ["corepack", "pnpm@https://e.example/p.tgz", "dlx", "x@1.0.0"],
    ["corepack", "pnpm@9.1.0\n", "dlx", "x@1.0.0"],
    # npm update and dedupe, with aliases and abbreviations.
    ["npm", "update"],
    ["npm", "up"],
    ["npm", "upgrade"],
    ["npm", "udpate"],
    ["npm", "upd"],
    ["npm", "dedupe"],
    ["npm", "ddp"],
    ["npm", "ded"],
    # compose and kube launch images named inside a file.
    ["docker", "compose", "up"],
    ["docker", "-c", "ctx", "compose", "up"],
    ["podman", "compose", "up"],
    ["podman", "kube", "play", "pod.yaml"],
    ["podman", "play", "kube", "pod.yaml"],
    # Transport-style image prefixes, by pattern and by name.
    ["podman", "run", "sif:/x@sha256:" + "a" * 64],
    ["podman", "run", "ostree:ref@sha256:" + "a" * 64],
    ["podman", "run", "tarball:/x.tar@sha256:" + "a" * 64],
    ["podman", "run", "oci-archive:/x@sha256:" + "a" * 64],
    ["podman", "run", "docker-archive:x@sha256:" + "a" * 64],
    ["podman", "run", "docker://img@sha256:" + "a" * 64],
    ["podman", "run", "newscheme:/x@sha256:" + "a" * 64],
])
def test_fix_round_2_bypass_is_refused(argv):
    assert refused(launchpolicy.package_version_problem(argv))


@pytest.mark.parametrize("argv", [
    ["corepack", "pnpm@9.1.0", "dlx", "x@1.0.0"],
    ["corepack", "pnpm@9.1.0+sha512.abc", "dlx", "x@1.0.0"],
    ["npm", "run", "start"],
    ["npm", "rebuild"],
    ["npm", "link"],
    ["npm", "pack"],
    ["docker", "container", "create", "evil:latest"],
    ["docker", "kube"],
    ["bun", "run", "server.ts"],
    ["pnpm", "exec", "tool"],
    ["docker", "-H", "tcp://h.example:2375", "run", "img@sha256:" + "a" * 64],
    ["podman", "run", "localhost:5000/img@sha256:" + "a" * 64],
    ["podman", "run", "alpine:3.19@sha256:" + "a" * 64],
    ["docker", "run", "registry.example:5000/team/img:1.0@sha256:" + "a" * 64],
])
def test_fix_round_2_control_is_accepted(argv):
    assert launchpolicy.package_version_problem(argv) is None


def _npm_package(root):
    npm = root / "lib" / "node_modules" / "npm"
    (npm / "bin").mkdir(parents=True)
    (npm / "lib").mkdir()
    (npm / "package.json").write_text('{"name": "npm", "main": "./index.js"}')
    for rel in ("bin/npm-cli.js", "bin/npx-cli.js", "index.js", "lib/cli.js"):
        (npm / rel).write_text("")
    dep = npm / "node_modules" / "node-gyp"
    (dep / "bin").mkdir(parents=True)
    (dep / "package.json").write_text('{"name": "node-gyp"}')
    (dep / "bin" / "node-gyp.js").write_text("")
    return npm


def _pipx_package(root):
    pipx = root / "lib" / "python3.12" / "site-packages" / "pipx"
    (pipx / "__pycache__").mkdir(parents=True)
    for rel in ("__main__.py", "main.py", "__pycache__/__main__.cpython-312.pyc",
                "__pycache__/main.cpython-312.pyc"):
        (pipx / rel).write_text("")
    return pipx


@pytest.mark.parametrize("args", [
    ["bin/npm-cli", "exec", "evil"],
    ["bin/npx-cli", "evil"],
    ["index", "exec", "evil"],
    [".", "exec", "evil"],
])
def test_node_resolves_extensions_and_directories_to_the_runner(tmp_path, args):
    npm = _npm_package(tmp_path)
    argv = ["node", str(npm / args[0])] + args[1:]
    assert refused(launchpolicy.package_version_problem(argv))
    pinned = argv[:-1] + [argv[-1] + "@1.2.3"]
    assert launchpolicy.package_version_problem(pinned) is None


@pytest.mark.parametrize("script", ["lib/cli.js", "lib/cli", "bin/../lib/cli.js"])
def test_other_files_inside_a_runner_package_are_refused(tmp_path, script):
    npm = _npm_package(tmp_path)
    assert launchpolicy.package_version_problem(["node", str(npm / script), "exec", "pkg@1.2.3"]) == \
        "run the runner by its standard name"
    link = tmp_path / "tool.js"
    link.symlink_to(npm / "lib" / "cli.js")
    assert launchpolicy.package_version_problem(["node", str(link), "exec", "pkg@1.2.3"]) == \
        "run the runner by its standard name"


def test_a_dependency_inside_a_runner_package_is_its_own_package(tmp_path):
    npm = _npm_package(tmp_path)
    script = npm / "node_modules" / "node-gyp" / "bin" / "node-gyp.js"
    assert launchpolicy.package_version_problem(["node", str(script), "rebuild"], tmp_path) is None


@pytest.mark.parametrize("script, expected", [
    ("__main__.py", "refused"),
    ("__pycache__/__main__.cpython-312.pyc", "refused"),
    (".", "refused"),
    ("main.py", "standard"),
    ("__pycache__/main.cpython-312.pyc", "standard"),
])
def test_python_scripts_inside_the_pipx_package(tmp_path, script, expected):
    pipx = _pipx_package(tmp_path)
    problem = launchpolicy.package_version_problem(["python3", str(pipx / script), "run", "evil"])
    if expected == "refused":
        assert refused(problem)
        assert launchpolicy.package_version_problem(["python3", str(pipx / script), "run", "pkg==1.0"]) is None
    else:
        assert problem == "run the runner by its standard name"



def test_node_directory_uses_package_json_main(tmp_path):
    """node DIR runs package.json main before index.js, so a main that is not a
    standard entry is refused even when index.js would be."""
    npm = _npm_package(tmp_path)
    (npm / "package.json").write_text('{"name": "npm", "main": "./lib/cli.js"}')
    assert launchpolicy.package_version_problem(["node", str(npm), "exec", "pkg@1.2.3"]) == \
        "run the runner by its standard name"


# ----- Task 12b fix round 3: allowlist grammar for node and python -----------------------

NPX_CLI = "/opt/homebrew/lib/node_modules/npm/bin/npx-cli.js"


@pytest.mark.parametrize("argv", [
    # node preloads, in "=" and separate-value forms, and every other option.
    ["node", f"--require={NPX_CLI}", "/lock/app.js", "evil"],
    ["node", "--require=/opt/homebrew/lib/node_modules/npm/bin/npx-cli", "/lock/app.js", "evil"],
    ["node", "--require=/opt/homebrew/lib/node_modules/corepack/dist/npx.js", "/lock/app.js", "evil"],
    ["node", f"--import={NPX_CLI}", "/lock/app.js", "evil"],
    ["node", f"--loader={NPX_CLI}", "/lock/app.js", "evil"],
    ["node", f"--experimental-loader={NPX_CLI}", "/lock/app.js", "evil"],
    ["node", "-r", NPX_CLI, "/lock/app.js", "evil"],
    ["node", "--require", NPX_CLI, "/lock/app.js", "evil"],
    ["node", "--import", NPX_CLI, "/lock/app.js", "evil"],
    ["node", "-e", "require('child_process')"],
    ["node", "-p", "1"],
    ["node", "--eval=1"],
    ["node", "--print", "1"],
    ["node", "--env-file=.env", "/lock/app.js"],
    ["node", "--env-file", ".env", "/lock/app.js"],
    ["node", "-C", "dev", "/lock/app.js"],
    ["node", "--conditions=dev", "/lock/app.js"],
    ["node", "--inspect", "/lock/app.js"],
    ["node", "--inspect-brk=9229", "/lock/app.js"],
    ["node", "--max-old-space-size=4g", "/lock/app.js"],
    ["node", "--", "/lock/app.js"],
    ["node", "-", "/lock/app.js"],
    ["node"],
    ["node", "--no-warnings"],
    # python stdlib launchers, attached and separate -m forms.
    ["python3", "-m", "runpy", "pipx", "run", "evil"],
    ["python3", "-Imrunpy", "uv", "tool", "run", "evil"],
    ["python3", "-m", "cProfile", "-m", "pipx", "run", "evil"],
    ["python3", "-m", "profile", "-m", "pipx", "run", "evil"],
    ["python3", "-m", "trace", "--count", "--module", "pipx", "run", "evil"],
    ["python3", "-m", "pdb", "-c", "continue", "-m", "pipx", "run", "evil"],
    ["python3", "-m", "timeit", "import pipx"],
    ["python3", "-m", "code"],
    ["python3", "-mcprofile", "x.py"],
    ["python3", "-m", "runpy.x"],
    # python options outside the allowlist.
    ["python3", "-c", "import pipx"],
    ["python3", "-Ic", "import pipx"],
    ["python3", "-W", "ignore", "server.py"],
    ["python3", "-X", "dev", "-m", "pipx", "run", "pkg==1.0"],
    ["python3", "-Xfrozen_modules=off", "server.py"],
    ["python3", "-i", "server.py"],
    ["python3", "-b", "server.py"],
    ["python3", "-d", "server.py"],
    ["python3", "-v", "server.py"],
    ["python3", "-x", "server.py"],
    ["python3", "-h"],
    ["python3", "--bogus", "-m", "pipx", "run", "pkg==1.0"],
    ["python3", "--check-hash-based-pycs", "always", "server.py"],
    ["python3", "--", "server.py"],
    ["python3", "-", "server.py"],
    ["python3"],
    ["python3", "-u"],
    ["python3", "-m"],
])
def test_interpreter_options_outside_the_allowlist_are_refused(argv):
    assert launchpolicy.package_version_problem(argv) == "put the code in a pinned file"


@pytest.mark.parametrize("argv", [
    ["python3", "{lock}/app.py"],
    ["python3", "app.py"],
    ["python3", "-IuB", "-OO", "-qsSEP", "server.py", "-c", "--anything"],
    ["python3", "-u", "server.py", "-m", "pipx"],
    ["node", "app.js"],
    ["node", "--max-old-space-size=4096", "app.js"],
    ["node", "--no-warnings", "--enable-source-maps", "--no-deprecation", "--stack-size=2048", "app.js", "--require=x"],
    ["node", "server.js", "npx-cli.js", "evilpkg"],
    ["node", "srv/index.js", "exec", "evil"],
    ["python3", "srv/__main__.py", "run", "evil"],
])
def test_interpreter_allowlist_controls_are_accepted(tmp_path, argv):
    for name in ("app.py", "server.py", "app.js", "server.js", "srv/index.js", "srv/__main__.py"):
        (tmp_path / name).parent.mkdir(exist_ok=True)
        (tmp_path / name).write_text("")
    argv = [a.format(lock=tmp_path) for a in argv]
    assert launchpolicy.package_version_problem(argv, tmp_path) is None


def test_allowlisted_option_before_a_runner_module_is_still_refused():
    assert refused(launchpolicy.package_version_problem(["python3", "-u", "-m", "pipx", "run", "pkg==1.0"]))
    assert refused(launchpolicy.package_version_problem(["python3", "-Im", "pipx", "run", "pkg==1.0"]))
    assert launchpolicy.package_version_problem(["python3", "-m", "pipx", "run", "pkg==1.0"]) is None


@pytest.mark.parametrize("name", ["NODE_OPTIONS", "PYTHONWARNINGS", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME",
                                  "NODE_PATH", "PYTHONINSPECT", "PYTHONSAFEPATH", "NODE_EXTRA_CA_CERTS",
                                  "pythonhome"])
def test_pinned_interpreter_env_outside_the_allowlist_is_refused_unless_empty(tmp_path, name):
    setup = project(tmp_path)
    out = io.StringIO()
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator", command=["python3", "x.py"],
                                      pin_env=[name])
    code = approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                           config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir,
                           environ={name: "1"})
    assert code == 2 and f"--pin-env {name} reaches an interpreter hook" in out.getvalue()
    with pytest.raises(approve_mod.ApproveError, match=f"--pin-env {name} reaches an interpreter hook"):
        approve_mod._validate(opts, {name: "x"}, datetime.now(timezone.utc))
    approve_mod._validate(opts, {name: ""}, datetime.now(timezone.utc))


@pytest.mark.parametrize("name, value", [("PYTHONUNBUFFERED", "1"), ("PYTHONIOENCODING", "utf-8"), ("PYTHONUTF8", "1"),
                                         ("NODE_ENV", "production"), ("NODE_NO_WARNINGS", "1"),
                                         ("APP_MODE", "on")])
def test_pinned_interpreter_env_on_the_allowlist_is_accepted(name, value):
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator", command=["python3", "x.py"],
                                      pin_env=[name])
    approve_mod._validate(opts, {name: value}, datetime.now(timezone.utc))


def test_path_form_argv0_inside_a_runner_package_is_refused(tmp_path):
    npm = _npm_package(tmp_path)
    (npm / "bin" / "npm-prefix.js").write_text("")
    assert launchpolicy.package_version_problem([str(npm / "bin" / "npm-prefix.js"), "exec", "x@1.0.0"]) == \
        "run the runner by its standard name"
    link = tmp_path / "tool"
    link.symlink_to(npm / "bin" / "npm-prefix.js")
    assert launchpolicy.package_version_problem([str(link)]) == "run the runner by its standard name"
    assert refused(launchpolicy.package_version_problem([str(npm / "bin" / "npm-cli.js"), "exec", "evil"]))
    assert launchpolicy.package_version_problem([str(npm / "bin" / "npm-cli.js"), "exec", "x@1.0.0"]) is None



STDLIB = __import__("sysconfig").get_paths()["stdlib"]


@pytest.mark.parametrize("argv", [
    # Standard-library launcher scripts by path pin nothing (fix round 4).
    ["python3", f"{STDLIB}/cProfile.py", "-m", "pipx", "run", "evil"],
    ["python3", f"{STDLIB}/profile.py", "-m", "pipx", "run", "evil"],
    ["python3", f"{STDLIB}/trace.py", "--count", "--module", "pipx", "run", "evil"],
    ["python3", f"{STDLIB}/pdb.py", "-c", "continue", "-m", "pipx", "run", "evil"],
    ["python3", f"{STDLIB}/timeit.py", "-s", "import pipx", "pass"],
    ["python3", f"{STDLIB}/code.py"],
    ["python3", "-u", f"{STDLIB}/runpy.py"],
    # Modules outside a pinned tree, the standard library included.
    ["python3", "-m", "profiling.tracing", "-m", "pipx", "run", "evil"],
    ["python3", "-m", "profiling.sampling", "run", "-m", "pipx", "run", "evil"],
    ["python3", "-m", "pip", "install", "evil"],
    ["python3", "-m", "venv", "--upgrade-deps", "v"],
    ["python3", "-m", "asyncio"],
    ["python3", "-m", "http.server"],
    ["python3", "-Imhttp.server"],
    ["python3", "-m", "notinatree"],
    # Module name shape.
    ["python3", "-m", "", "x"],
    ["python3", "-um", "-I", "x"],
    ["python3", "-m", "my-module"],
    ["python3", "-m", "mymodule."],
    ["python3", "-m", "mymodule\n"],
    ["python3", "-m", "../mymodule"],
    # Scripts that are not pinned.
    ["python3", "missing.py"],
    ["python3", "/elsewhere/app.py"],
    ["python3", "outside.py"],
    ["python3", "pkgdir"],
    ["node", "missing.js"],
    ["node", "app"],
    ["node", "/elsewhere/app.js"],
])
def test_unpinned_python_and_node_code_is_refused(tmp_path, argv):
    lock = tmp_path / "lock"
    (lock / "pkgdir").mkdir(parents=True)
    (lock / "pkgdir" / "__main__.py").write_text("")
    (lock / "app.js").write_text("")
    (lock / "notinatree.py").write_text("")
    (lock / "src").mkdir()
    for name in ("pip", "profiling", "http", "asyncio"):
        (lock / "src" / name).mkdir()
    (lock / "src" / "venv.py").write_text("")
    (tmp_path / "outside.py").write_text("")
    (lock / "outside.py").symlink_to(tmp_path / "outside.py")
    assert launchpolicy.package_version_problem(argv, lock, ["src"]) == "put the code in a pinned file"


def test_stdlib_launcher_module_is_refused_through_approve(tmp_path):
    setup = project(tmp_path)
    out = io.StringIO()
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator",
                                      command=["python3", "-m", "cProfile", "-m", "pipx", "run", "evil"])
    code = approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                           config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir, environ={})
    assert code == 2 and "put the code in a pinned file" in out.getvalue()


def test_a_script_without_a_lock_directory_is_refused():
    assert launchpolicy.package_version_problem(["python3", "app.py"]) == "put the code in a pinned file"
    assert launchpolicy.package_version_problem(["node", "app.js"]) == "put the code in a pinned file"


def _fake_venv(root, name=".venv"):
    """A minimal venv layout with a byte copy of the real interpreter. approve
    never runs it: the -m rule reads only the layout."""
    import os
    import shutil
    venv = root / name
    (venv / "bin").mkdir(parents=True)
    shutil.copy2(os.path.realpath(sys.executable), venv / "bin" / "python3")
    (venv / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
    site = venv / "lib" / "python3.12" / "site-packages"
    (site / "mymodule").mkdir(parents=True)
    (site / "flatmod.py").write_text("")
    return venv, site


@pytest.mark.parametrize("argv, trees", [
    ([".venv/bin/python3", "-u", "-m", "mymodule"], [".venv"]),
    (["{lock}/.venv/bin/python3", "-m", "mymodule.server", "--port", "1"], [".venv"]),
    ([".venv/bin/python3", "-m", "flatmod"], [".venv"]),
    ([".venv/bin/python3", "-mmymodule"], ["."]),
    (["python3", "pkgdir"], ["pkgdir"]),
    (["node", "app"], ["."]),
    (["node", "nodepkg"], ["nodepkg"]),
])
def test_code_in_a_pinned_tree_is_accepted(tmp_path, argv, trees):
    _fake_venv(tmp_path)
    (tmp_path / "pkgdir").mkdir()
    (tmp_path / "pkgdir" / "__main__.py").write_text("")
    (tmp_path / "app.js").write_text("")
    (tmp_path / "nodepkg").mkdir()
    (tmp_path / "nodepkg" / "index.js").write_text("")
    argv = [a.format(lock=tmp_path) for a in argv]
    assert launchpolicy.package_version_problem(argv, tmp_path, trees) is None


@pytest.mark.parametrize("argv, trees", [
    # A system python3 searches only its own site-packages, which nothing pins.
    (["python3", "-m", "mymodule"], [".venv"]),
    (["python3", "-u", "-m", "mymodule"], ["src", ".venv"]),
    (["/usr/bin/python3", "-m", "mymodule"], [".venv"]),
    # The venv interpreter is not in a pinned tree.
    ([".venv/bin/python3", "-m", "mymodule"], ["src"]),
    ([".venv/bin/python3", "-m", "mymodule"], []),
    # A module at a tree root, not in the interpreter's site-packages.
    ([".venv/bin/python3", "-m", "treemod"], [".venv", "src"]),
    ([".venv/bin/python3", "-m", "absent"], [".venv"]),
    # Standard-library names from any supported version load first.
    ([".venv/bin/python3", "-m", "asyncore"], [".venv"]),
    ([".venv/bin/python3", "-m", "distutils"], [".venv"]),
    ([".venv/bin/python3", "-m", "profiling.tracing", "-m", "pipx"], [".venv"]),
    ([".venv/bin/python3", "-m", "__phello__"], [".venv"]),
    ([".venv/bin/python3", "-m", "http.server"], [".venv"]),
    ([".venv/bin/python3", "-m", "pip", "install", "evil"], [".venv"]),
])
def test_a_module_outside_a_pinned_venv_is_refused(tmp_path, argv, trees):
    _venv, site = _fake_venv(tmp_path)
    (tmp_path / "src" / "mymodule").mkdir(parents=True)
    (tmp_path / "src" / "treemod").mkdir()
    (tmp_path / ".venv" / "treemod.py").write_text("")
    for name in ("asyncore", "distutils", "profiling", "__phello__", "http", "pip"):
        (site / name).mkdir()
    assert launchpolicy.package_version_problem(argv, tmp_path, trees) == "put the code in a pinned file"


def test_a_symlinked_venv_interpreter_or_module_is_refused(tmp_path):
    import os
    venv, site = _fake_venv(tmp_path)
    (tmp_path / "outside").mkdir()
    (site / "evilmod").symlink_to(tmp_path / "outside")
    assert launchpolicy.package_version_problem([".venv/bin/python3", "-m", "evilmod"], tmp_path, [".venv"]) == \
        "put the code in a pinned file"
    (venv / "bin" / "python3").unlink()
    (venv / "bin" / "python3").symlink_to(os.path.realpath(sys.executable))
    assert launchpolicy.package_version_problem([".venv/bin/python3", "-m", "mymodule"], tmp_path, [".venv"]) == \
        "put the code in a pinned file"


def test_a_module_or_script_outside_every_pinned_tree_is_refused(tmp_path):
    (tmp_path / "other").mkdir()
    (tmp_path / "pkgdir").mkdir()
    (tmp_path / "pkgdir" / "__main__.py").write_text("")
    (tmp_path / "nodepkg").mkdir()
    (tmp_path / "nodepkg" / "index.js").write_text("")
    assert launchpolicy.package_version_problem(["python3", "pkgdir"], tmp_path, ["other"]) == \
        "put the code in a pinned file"
    assert launchpolicy.package_version_problem(["node", "nodepkg"], tmp_path, ["other"]) == \
        "put the code in a pinned file"


def test_the_stdlib_list_is_vendored_across_versions():
    names = launchpolicy._PY_UNPINNABLE_MODULES
    for name in ("asynchat", "asyncore", "imp", "distutils", "smtpd", "cgi", "cgitb", "crypt", "imghdr",
                 "mailcap", "msilib", "nis", "nntplib", "ossaudiodev", "pipes", "sndhdr", "spwd", "sunau",
                 "telnetlib", "uu", "xdrlib", "lib2to3", "audioop", "chunk", "profiling", "__hello__",
                 "__phello__", "runpy", "asyncio", "venv", "sys", "_frozen_importlib", "pip"):
        assert name.casefold() in names
    assert set(n.casefold() for n in sys.stdlib_module_names) <= names
    assert "mymodule" not in names


def test_the_lock_directory_matches_by_device_and_inode(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "app.py").write_text("")
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    assert launchpolicy.package_version_problem(["python3", str(alias / "app.py")], real) is None
    assert launchpolicy.package_version_problem(["python3", str(real / "app.py")], alias) is None


def test_pin_trees_reach_package_version_problem_through_approve(tmp_path):
    setup = project(tmp_path)
    _fake_venv(setup.lock_dir)
    out = io.StringIO()
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator",
                                      command=[".venv/bin/python3", "-m", "mymodule"], pin_trees=[".venv"])
    approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                    config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir, environ={})
    assert "put the code in a pinned file" not in out.getvalue()


@pytest.mark.parametrize("name", ["LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
                                  "BASH_ENV", "ENV", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "PERL5OPT", "RUBYOPT",
                                  "JDK_JAVA_OPTIONS", "PERL5LIB", "RUBYLIB", "OPENSSL_CONF", "GCONV_PATH",
                                  "LUA_INIT", "LUA_INIT_5_4", "lua_init_5_3", "perl5lib",
                                  "ld_preload", "dyld_insert_libraries", "bash_env", "PERLLIB", "PERL5DB",
                                  "OPENSSL_MODULES", "OPENSSL_ENGINES", "CLASSPATH", "classpath"])
def test_pinned_code_loading_env_is_refused_unless_empty(tmp_path, name):
    setup = project(tmp_path)
    out = io.StringIO()
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator", command=["python3", "x.py"],
                                      pin_env=[name])
    code = approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                           config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir,
                           environ={name: "/x/evil.so"})
    assert code == 2 and f"--pin-env {name} loads code into the server" in out.getvalue()
    with pytest.raises(approve_mod.ApproveError, match=f"--pin-env {name} loads code into the server"):
        approve_mod._validate(opts, {name: "x"}, datetime.now(timezone.utc))
    approve_mod._validate(opts, {name: ""}, datetime.now(timezone.utc))


@pytest.mark.parametrize("name", ["LDFLAGS", "DYLDX", "ENVIRONMENT", "MY_ENV", "RUBY_OPT", "LUA_PATHX",
                                  "OPENSSL_CONFX", "PERL5LIBRARY"])
def test_names_near_the_code_loading_env_are_accepted(name):
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator", command=["python3", "x.py"],
                                      pin_env=[name])
    approve_mod._validate(opts, {name: "on"}, datetime.now(timezone.utc))


@pytest.mark.parametrize("name", ["PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"])
@pytest.mark.parametrize("value, message", [("1", "--pin-env {name} reaches an interpreter hook"),
                                            ("", "{name} is set by the proxy and cannot be pinned")])
def test_a_proxy_fixed_python_variable_cannot_be_pinned_through_approve(tmp_path, name, value, message):
    setup = project(tmp_path)
    out = io.StringIO()
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator",
                                      command=["python3", "fake_mcp_server.py"], pin_env=[name])
    code = approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                           config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir,
                           environ={name: value})
    assert code == 2 and message.format(name=name) in out.getvalue()


@pytest.mark.parametrize("name", ["PYTHONPATH", "PYTHONUNBUFFERED", "pythonhome", "NODE_OPTIONS", "node_env",
                                  "LD_PRELOAD", "dyld_insert_libraries", "BASH_ENV", "OPENSSL_CONF", "LUA_INIT_5_4",
                                  "PERL5LIB", "rubylib", "PERLLIB", "PERL5DB", "OPENSSL_MODULES", "OPENSSL_ENGINES",
                                  "CLASSPATH"])
def test_a_hook_variable_cannot_be_secret(tmp_path, name):
    setup = project(tmp_path)
    out = io.StringIO()
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator",
                                      command=["python3", "fake_mcp_server.py"], secret_env=[name])
    code = approve_mod.run(opts, confirm=lambda p: "fetch", passphrase=lambda: PASS, out=out,
                           config_dir=setup.config, state_dir=setup.state, cwd=setup.lock_dir, environ={name: "v"})
    assert code == 2 and f"--secret-env {name} loads code into the server" in out.getvalue()
    assert launchpolicy.env_problem({}, [name]) is not None


def test_an_ordinary_secret_passes_the_env_rules():
    assert launchpolicy.env_problem({"APP_MODE": "on"}, ["API_TOKEN", "PYTHON_KEY_X"[7:]]) is None


@pytest.mark.parametrize("tree", [".", "./", "srv/..", "here"])
def test_a_pinned_tree_that_holds_the_lock_file_is_refused(tmp_path, tree):
    """Final review A2: signing rewrites the lock, so a tree that contains it
    could never pass the proxy's tree check."""
    setup = project(tmp_path)
    (setup.lock_dir / "srv").mkdir()
    (setup.lock_dir / "here").symlink_to(".")
    code, out = approve(setup, pin_trees=[tree])
    assert code == 2
    assert "the lock file is inside this tree and changes when it is signed. Pin a subdirectory" in out
    assert "fetch" not in json.loads((setup.lock_dir / "cxbom.lock").read_text())["servers"]


def test_a_pinned_subdirectory_beside_the_lock_file_is_accepted(tmp_path):
    setup = project(tmp_path)
    (setup.lock_dir / "srv").mkdir()
    (setup.lock_dir / "srv" / "x.py").write_text("")
    code, out = approve(setup, pin_trees=["srv"])
    assert code == 0, out


_THROUGH = "directly, not through"


@pytest.mark.parametrize("argv", [
    ["env", "npx", "evil"], ["/usr/bin/env", "uvx", "evil"], ["nice", "uvx", "evil"],
    ["timeout", "5", "npx", "evil@latest"], ["nohup", "npx", "evil"], ["stdbuf", "-oL", "npx", "evil"],
    ["ENV", "npx", "evil"], ["Nice", "-n", "5", "uvx", "evil"], ["env", "FOO=1", "npx", "evil"],
    ["nice", "env", "npx", "evil"], ["nice", "sh", "script.sh"], ["timeout", "5", "python3", "-m", "pipx", "run", "x"],
    ["nice", "node", "npx-cli.js", "evil"], ["nice", "/usr/local/lib/node_modules/npm/bin/npx-cli.js", "evil"],
    ["nohup", "'npx'", "evil"], ["stdbuf", "-oL", "corepack", "npm@10.0.0", "exec", "x"],
    ["bash", "npx", "evil"], ["nice", "bash", "-c", "n''px evil"]])
def test_a_runner_behind_an_exec_wrapper_is_refused(argv):
    """Final review A3: a wrapper hides the runner from the argv[0] grammar."""
    problem = launchpolicy.package_version_problem(argv)
    assert problem is not None and problem.startswith("run ") and _THROUGH in problem, problem


@pytest.mark.parametrize("argv", [
    ["sh", "-c", "npx evil"], ["bash", "-c", "true"], ["zsh", "-c", "true"], ["dash", "-c", "true"],
    ["ksh", "-c", "true"], ["bash", "-lc", "true"], ["sh", "-e", "-c", "true"], ["bash", "--norc", "-c", "true"],
    ["env", "-S", "npx evil"], ["env", "-iS", "true"], ["env", "--split-string=true"], ["/bin/SH", "-c", "true"]])
def test_a_command_string_behind_a_shell_or_env_is_refused(argv):
    assert launchpolicy.package_version_problem(argv) == "put the code in a pinned file"


def test_a_wrapper_under_another_name_is_matched_by_its_realpath(tmp_path):
    import shutil
    link = tmp_path / "run"
    link.symlink_to(shutil.which("env", path="/usr/bin:/bin"))
    problem = launchpolicy.package_version_problem([str(link), "npx", "evil"])
    assert problem is not None and _THROUGH in problem


@pytest.mark.parametrize("argv", [["nice", "./server"], ["env"], ["bash", "server.sh"], ["timeout", "5", "./srv", "-v"]])
def test_a_wrapper_around_a_plain_program_is_accepted(argv):
    assert launchpolicy.package_version_problem(argv) is None


def test_a_file_inside_a_runner_package_behind_a_wrapper_is_refused(tmp_path):
    npm = _npm_package(tmp_path)
    assert launchpolicy.package_version_problem(["nice", str(npm / "lib" / "cli.js"), "exec", "x"]) == \
        "run the runner by its standard name"


def _home_venv_layout(home):
    """A bare interpreter in <home>/.local/bin, on the trusted search path,
    whose site-packages lies under <home>/.local/lib."""
    import os
    import stat
    bin_dir = home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    interpreter = bin_dir / "python-cxbom-a4"
    interpreter.write_text("")
    interpreter.chmod(interpreter.stat().st_mode | stat.S_IXUSR)
    module = home / ".local" / "lib" / "python3.12" / "site-packages" / "mymod"
    module.mkdir(parents=True)
    (module / "__init__.py").write_text("")
    assert os.access(interpreter, os.X_OK)
    return ["python-cxbom-a4", "-m", "mymod"]


def test_an_m_module_needs_its_interpreter_directory_in_a_pinned_tree(tmp_path, monkeypatch):
    """Final review A4: the lock directory is the home directory, and only
    .local/lib is pinned. The module lies in a pinned tree, but the
    interpreter in ~/.local/bin does not, so -m is refused."""
    monkeypatch.setattr(paths, "pw_dir", lambda: tmp_path)
    argv = _home_venv_layout(tmp_path)
    assert launchpolicy.package_version_problem(argv, tmp_path, [".local/lib"]) == "put the code in a pinned file"
    assert launchpolicy.package_version_problem(argv, tmp_path, [".local"]) is None


_DIGEST_IMAGE = "img@sha256:" + "a" * 64
_GOOD_SECTION = {"long": {"interactive": "bool"}, "short": {"i": "interactive"}}


@pytest.mark.parametrize("text", [
    "not json", "[]", "{}",
    json.dumps({"docker_global": _GOOD_SECTION, "docker": {"long": {}}, "podman": _GOOD_SECTION}),
    json.dumps({"docker_global": _GOOD_SECTION, "docker": _GOOD_SECTION, "podman": {"long": [], "short": {}}}),
    json.dumps({"docker_global": _GOOD_SECTION, "docker": dict(_GOOD_SECTION, short={"i": ["x"]}),
                "podman": _GOOD_SECTION}),
    json.dumps({"docker_global": _GOOD_SECTION, "docker": dict(_GOOD_SECTION, alias=[]), "podman": _GOOD_SECTION}),
    OSError("gone")])
@pytest.mark.parametrize("runner", ["docker", "podman"])
def test_a_malformed_container_flag_table_is_a_refusal_not_an_exception(monkeypatch, text, runner):
    """Final review A5: the table loader raised an undefined ApproveError,
    and a table missing a section raised a bare KeyError."""
    def load():
        if isinstance(text, Exception):
            raise text
        return text
    monkeypatch.setattr(launchpolicy, "_load_flag_text", load)
    assert launchpolicy.package_version_problem([runner, "run", "-i", _DIGEST_IMAGE]) == \
        "the container flag table cannot be read"


def test_the_vendored_container_flag_table_passes_the_shape_check():
    assert launchpolicy.package_version_problem(["docker", "run", "-i", _DIGEST_IMAGE]) is None
    assert launchpolicy.package_version_problem(["podman", "run", "-i", _DIGEST_IMAGE]) is None


def test_client_capabilities_past_the_safe_integer_range_are_a_usage_error(tmp_path):
    """Final review A5: object_sha256 raised CanonicalizationError out of approve."""
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator", command=["python3", "x.py"],
                                      client_capabilities={"experimental": {"n": 2 ** 53 + 1}})
    with pytest.raises(approve_mod.ApproveError, match="--client-capabilities cannot be canonicalized"):
        approve_mod._validate(opts, {}, datetime.now(timezone.utc))
    setup = project(tmp_path)
    code, out = approve(setup, client_capabilities={"n": 2 ** 60})
    assert code == 2 and "--client-capabilities cannot be canonicalized" in out


def test_the_review_summary_escapes_argv(tmp_path):
    """Final review A6: argv is shown the way every other untrusted string is."""
    setup = project(tmp_path)
    setup.argv = setup.argv + ["x\u202ey\u200bz\u009b"]
    code, out = approve(setup)
    assert code == 0, out
    assert "x\\u{202E}y\\u{200B}z\\u{009B}" in out
    assert not any(ch in out for ch in "\u202e\u200b\u009b")


def test_a_failed_lock_write_leaves_the_high_water_mark_alone(tmp_path, monkeypatch):
    """Final review A7: the mark moved before write_lock, so a failed write
    left it ahead of the lock on disk."""
    setup = project(tmp_path)

    def fail(path, lock):
        raise OSError(28, "No space left on device", str(path))

    monkeypatch.setattr(lockfile, "write_lock", fail)
    code, out = approve(setup)
    assert code == 2 and "No space left on device" in out
    marks = setup.state / signing.HIGHWATER_FILE
    assert not marks.exists() or "fetch" not in marks.read_text()


@pytest.mark.parametrize("argv", [
    ["env", "-u", "X", "--", "npx", "evil"], ["timeout", "5s", "NPX", "evil"], ["env", "-vS", "npx evil"],
    ["env", "--sp=npx evil"], ["nohup", "./node_modules/.bin/npx", "evil"], ["BASH", "-c", "true"],
    ["bash", "-O", "extglob", "-c", "true"], ["nice", "-n", "5", "--", "python3", "-c", "import os"],
    ["stdbuf", "-o0", "/opt/homebrew/bin/uvx", "evil"]])
def test_more_wrapper_variants_are_refused(argv):
    assert launchpolicy.package_version_problem(argv) is not None


def test_a_lock_directory_symlink_to_a_runner_behind_a_wrapper_is_refused(tmp_path):
    npm = _npm_package(tmp_path / "global")
    lock_dir = tmp_path / "proj"
    lock_dir.mkdir()
    (lock_dir / "safe").symlink_to(npm / "bin" / "npx-cli.js")
    problem = launchpolicy.package_version_problem(["nice", "safe", "evil"], lock_dir)
    assert problem is not None and _THROUGH in problem


def test_the_proxy_re_applies_the_wrapper_rule_to_a_signed_entry(tmp_path):
    """An entry signed before the wrapper rule existed is refused at launch."""
    import shutil
    from cxbom import launch
    if shutil.which("nice", path=":".join(launch.trusted_search_path())) is None:
        pytest.skip("no nice on the trusted search path")
    lock_dir = tmp_path / "proj"
    lock_dir.mkdir()
    argv = ["nice", "npx", "evil"]
    pins = launch.compute_launch_pins(argv, lock_dir, {})
    with pytest.raises(launch.LaunchError) as ei:
        launch.check_launch(pins, argv, lock_dir, {}, "fetch")
    assert ei.value.item == "policy" and _THROUGH in str(ei.value)
