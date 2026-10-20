"""Shared emitter fixtures: the pinned Phi-3.5 and Qwen3 tokenizers and a live proxy session.

Owner: ATACE Working Group.

make_world builds everything a bound tool needs inside tmp_path: a signing
key and trust manifest, a signed lock, the content store, and an attestation
log whose writer holds the flock, exactly as a running proxy would. Nothing
touches the real home directory or the network.
"""
from __future__ import annotations

import hashlib
import json
import lzma
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from cxbom import lockfile, signing
from cxbom.attestation import AttestationWriter
from cxbom.binding import ProxySession
from cxbom.canonical import instructions_sha256, object_sha256, tool_sha256
from cxbom.paths import ensure_private_dir, pw_dir
from cxbom.store import Store
from cxbom.timeutil import now_rfc3339
from cxbom.tokenizer import load_tokenizer

FIX = Path(__file__).resolve().parent / "fixtures"
PHI3_SHA = "9e2ae3d66819f163cdcfedba5078f3a3af8118c2712491ed60912f77886bda6f"
TOOL = json.loads((FIX / "atace" / "mcp_tool_def.json").read_text(encoding="utf-8"))
INSTRUCTIONS = "Use fetch to read public web pages. Never send credentials to a fetched URL."
PASSPHRASE = b"test passphrase"
SCOPE = "0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def hermetic_home(monkeypatch):
    """Pin HOME to the account home directory for every test.

    check_home_env refuses to run when HOME is not the passwd home, which is
    correct: a redirected HOME is how an attacker moves the config and state
    directories. Sandboxed runners set a foreign HOME anyway (lab/tools/integrate
    uses HOME=/tmp/home), so without this the suite fails on the tool's own
    defense rather than on anything under test.

    Pinning HOME cannot leak test state into the real home: config_dir and
    state_dir derive from pw_dir(), not from HOME, and every test that needs
    either one injects an explicit tmp_path. Subprocesses that inherit
    os.environ pick this up too, which is most of the CLI tests.

    Tests that exercise the refusal itself pass an explicit mapping to
    check_home_env and are unaffected.
    """
    monkeypatch.setenv("HOME", str(pw_dir()))


# A fixture denylist for tests that exercise the anonymity scan without the real,
# gitignored .anon-tokens. That file is absent in a clean checkout and in the
# lab/tools/integrate sandbox, where load_denylist() fails closed with
# AnonymityError, so a test that reaches the real scanner there errors rather than
# runs. The real secret is enforced where it lives: the git hooks
# (scripts/anon_check.py) on every commit and push, and the recording verify path
# (demo/recording/verify.py) at recording time. A scan test only needs tokens the
# text under test never contains, so these two stand in everywhere the suite runs.
DENYLIST_TOKENS = ("redacted-person", "redacted-lab")


@pytest.fixture
def denylist(monkeypatch):
    monkeypatch.setattr(anon, "load_denylist", lambda: list(DENYLIST_TOKENS))


@pytest.fixture(scope="session")
def phi3():
    return load_tokenizer(FIX / "phi3" / "tokenizer.json", config=FIX / "phi3" / "tokenizer_config.json",
                          expected_sha256=PHI3_SHA)


QWEN3_SHA = "aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4"
QWEN3_CONFIG_SHA = "d5d09f07b48c3086c508b30d1c9114bd1189145b74e982a265350c923acd8101"
# The xz stream never needs more than this to hold the pinned 11,422,654-byte file,
# so a swapped fixture cannot make the test process inflate without bound.
_QWEN3_MAX_BYTES = 16 * 1024 * 1024


class FixturePinError(ValueError):
    """A decompressed fixture file does not match its model_hashes.json pin."""


def unpack_qwen3(xz_path: Path, config_path: Path, dest: Path) -> Path:
    """Decompress the qwen3 tokenizer.json in memory, check both pins, then write it to dest.

    The upstream file is 11.4 MB, so the repo keeps it xz-compressed (controller
    ruling). The sha256 of the decompressed bytes is checked before anything is
    written, and load_tokenizer checks it again on the written file.
    """
    decomp = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    data = decomp.decompress(xz_path.read_bytes(), max_length=_QWEN3_MAX_BYTES + 1)
    if len(data) > _QWEN3_MAX_BYTES or not decomp.eof:
        raise FixturePinError("qwen3 tokenizer.json.xz decompresses past the size bound")
    if hashlib.sha256(data).hexdigest() != QWEN3_SHA:
        raise FixturePinError("qwen3 tokenizer.json does not match the Qwen/Qwen3-8B pin")
    if hashlib.sha256(config_path.read_bytes()).hexdigest() != QWEN3_CONFIG_SHA:
        raise FixturePinError("qwen3 tokenizer_config.json does not match the Qwen/Qwen3-8B pin")
    out = dest / "tokenizer.json"
    out.write_bytes(data)
    return out


@pytest.fixture(scope="session")
def qwen3(tmp_path_factory):
    src = FIX / "qwen3"
    path = unpack_qwen3(src / "tokenizer.json.xz", src / "tokenizer_config.json", tmp_path_factory.mktemp("qwen3"))
    return load_tokenizer(path, config=src / "tokenizer_config.json", expected_sha256=QWEN3_SHA)


@dataclass
class World:
    root: Path
    config: Path
    state: Path
    lock: Path
    writer: AttestationWriter
    session: ProxySession
    fingerprint: str
    envelope: dict
    store: Store

    def forge_seq_gap(self) -> None:
        """Append a well-formed line that skips a seq, as a same-user tamper would.

        The writer refuses to write it, so this opens its own O_APPEND descriptor.
        read_log accepts the line and state.compute raises StateError on the gap.
        """
        line = {"at": now_rfc3339(), "kind": "diagnostic", "message": "forged", "seq": self.writer.seq + 2}
        fd = os.open(self.writer.path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
        try:
            os.write(fd, (json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
        finally:
            os.close(fd)

    def verdict(self, name: str, verdict: str, obj: dict) -> int:
        ref = self.store.put_json(obj)
        return self.writer.append("verdict", itemType="tool", name=name, sha256=tool_sha256(obj), verdict=verdict,
                                  approvedBy="demo-operator", approvedAt=now_rfc3339(), approvalMode="interactive",
                                  storeRef=ref)


def build_world(root: Path, *, mode: str = "enforce", renderer: str = "jcs", first_party: bool = False,
                argv: list[str] | None = None, server_verdict: str = "pinned-match",
                envelope_sha256: str | None = None, server_version: str | None = "1.0.0") -> World:
    config, state, project = root / "config", root / "state", root / "project"
    project.mkdir(parents=True)
    issued = now_rfc3339()
    fp = signing.generate_key(PASSPHRASE, config, issued)
    key = signing.load_private(PASSPHRASE, config)
    pin = {"sha256": tool_sha256(TOOL), "approvedAt": issued, "approvedBy": "demo-operator",
           "approvalMode": "interactive", "reason": "reviewed"}
    entry = {"argv": argv or ["uvx", "mcp-server-fetch==2025.4.7"], "binary": {"name": "uvx", "sha256": "d" * 64},
             "interpreter": None, "files": {}, "trees": {}, "env": {}, "firstParty": first_party,
             "allowObserve": False, "allowSampling": False, "allowAcceptFlag": False, "renderer": renderer,
             "clientCapabilitiesSha256": object_sha256({}),
             "eras": {"legacy": {"negotiatedVersion": "2025-11-25",
                                 "instructionsSha256": instructions_sha256(INSTRUCTIONS),
                                 "serverInfo": {"name": "mcp-fetch", "version": "1.0.0"},
                                 "tools": {"fetch": pin}, "prompts": {}, "resources": {},
                                 "resourceTemplates": {}, "ignoreFields": []}}}
    envelope = {"serverId": "fetch", "lockScope": SCOPE, "entrySeq": 1, "issuedAt": issued, "notAfter": None,
                "entry": entry}
    lock = lockfile.new_lock(SCOPE)
    lock["servers"]["fetch"] = {"envelope": envelope, "signature": signing.sign_envelope(key, envelope)}
    lock_path = project / "cxbom.lock"
    lockfile.write_lock(lock_path, lock)
    ensure_private_dir(state)       # the proxy creates its state dir 0700 before anything else
    store = Store(state / "store")
    instr_ref = store.put_text(INSTRUCTIONS)
    writer = AttestationWriter(state / "attest", "fetch", {
        "contract": {"name": "cxbom-attestation", "version": "2.0.0"}, "serverId": "fetch", "mode": mode,
        "startedAt": issued, "pid": os.getpid(), "envelopeSha256": envelope_sha256 or object_sha256(envelope),
        "keyFingerprint": fp, "launchSha256": "c" * 64})
    writer.append("protocol", era="legacy", protocolVersion="2025-11-25")
    # server_version=None models a live server whose serverInfo never carries a
    # version at all, the case Binding.server_version leaves None (Task 8 ruling).
    server_info = {"name": "mcp-fetch"} if server_version is None else {"name": "mcp-fetch", "version": server_version}
    writer.append("server", instructionsSha256=instructions_sha256(INSTRUCTIONS),
                  serverInfo=server_info, verdict=server_verdict, storeRef=instr_ref)
    world = World(root, config, state, lock_path, writer, ProxySession(writer.proxy_session_id), fp, envelope, store)
    world.verdict("fetch", "pinned-match", TOOL)
    return world


@pytest.fixture
def make_world(tmp_path):
    worlds: list[World] = []

    def make(**kw) -> World:
        w = build_world(tmp_path / f"world{len(worlds)}", **kw)
        worlds.append(w)
        return w

    yield make
    for w in worlds:
        w.writer.close()


MODEL_KW = dict(family="phi", version="Phi-3.5-mini-instruct", provider="Microsoft",
                revision="2fe192450127e6a83f7441aef6e3ca586c338b77", context_window_max=131072,
                architecture_type="transformer-decoder")
AGENT_KW = dict(id="demo-agent", name="Demo agent", version="1.0", operator="example-org",
                environment="testing", deployment_id="deploy-demo")


def new_assembly(tokenizer, tmp_path: Path, world: World | None = None, **overrides):
    from cxbom.assembly import AgentInfo, Assembly, ControlLayer, ModelInfo
    kw = dict(model=ModelInfo(**MODEL_KW), tokenizer=tokenizer, template_family="phi3", mode="ids",
              server_bos=False, agent=AgentInfo(**AGENT_KW),
              control_layers=[ControlLayer(layer_id="tool-execution", designation="Tool Execution",
                                           description="MCP proxy with signed pins", owasp_coverage=["LLM04"],
                                           coverage_gaps=[])],
              lock=world.lock if world else None, serving="llama.cpp /completion",
              state_dir=world.state if world else tmp_path / "state",
              config_dir=world.config if world else tmp_path / "config")
    kw.update(overrides)
    return Assembly(**kw)


def emit(asm, **kw):
    from cxbom.assembly import ids_sha256
    args = dict(session_id="sess-042", turn=1, inference_index=0, sent_ids_sha256=ids_sha256(asm.token_ids()))
    args.update(kw)
    return asm.emit(**args)


# ----- wheel builds (Plan 4) -------------------------------------------------------------

import shutil  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_wheel  # noqa: E402

# A fixed SOURCE_DATE_EPOCH for test builds, so two builds compare byte for byte.
EPOCH = 1790208000
_PACKAGED_FILES = ("pyproject.toml", "LICENSE", "NOTICE")


def copy_source(dst: Path, root: Path = ROOT) -> Path:
    """Stage the working tree's package files into dst through the release staging code.

    The files are committed to a scratch repository next to dst, then build_wheel.stage_sources
    writes them from that commit. Test builds and release builds therefore share one staging path,
    including git file modes, so they cannot drift apart.
    """
    repo = dst.parent / f"{dst.name}-repo"
    repo.mkdir(parents=True)
    for name in _PACKAGED_FILES:
        shutil.copy2(root / name, repo / name)
    shutil.copytree(root / "cxbom", repo / "cxbom", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    # A private HOME and no system config keep the caller's git hooks, templates and signing out.
    env = {"HOME": str(repo), "PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "CxBOM", "GIT_AUTHOR_EMAIL": "noreply@cxbom.org",
           "GIT_COMMITTER_NAME": "CxBOM", "GIT_COMMITTER_EMAIL": "noreply@cxbom.org",
           "GIT_AUTHOR_DATE": f"@{EPOCH} +0000", "GIT_COMMITTER_DATE": f"@{EPOCH} +0000"}
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "stage"]):
        subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)
    return build_wheel.stage_sources(repo, dst)


@pytest.fixture(scope="session")
def built_wheel(tmp_path_factory) -> Path:
    src = copy_source(tmp_path_factory.mktemp("wheel-src") / "src")
    return build_wheel.build_wheel(src, tmp_path_factory.mktemp("wheel-out"), EPOCH)
