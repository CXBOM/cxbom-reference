"""The proxy and the emitter meet at one session key, and the wheel runs the CLI (Plan 4).

Owner: ATACE Working Group. Needs Plan 2: cxbom.relay, cxbom.cli, cxbom/__main__.py,
tests/proxy_helpers.py and tests/fake_mcp_server.py.
"""
import importlib.util
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_mcp_server as fake  # noqa: E402
from proxy_helpers import ROOT, ProxyProcess, init, note, rpc, signed_setup  # noqa: E402

from cxbom import binding, relay  # noqa: E402


def test_the_proxy_and_the_emitter_share_one_session_meta_key():
    # relay.py and binding.py each define the literal, so this is a real
    # cross-module check, not one constant compared with itself. A rename on
    # either side silently unbinds every recording from its proxy session.
    assert relay.SESSION_META_KEY == binding.SESSION_META_KEY == "org.cxbom/proxySessionId"


def load_second_copy(path: Path, name: str, monkeypatch):
    """Load an independent copy of a module file, so a patched dependency is visible in it.

    Importing the module again under its own name would return the cached one,
    whose constants were bound at first import. The copy is registered in
    sys.modules while it executes, because @dataclass resolves annotations
    through the module entry, and monkeypatch removes it again afterwards.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(not (ROOT / "demo" / "gonogo.py").is_file(),
                    reason="the go/no-go lives with the demonstration in the development repository")
def test_the_gonogo_takes_the_legacy_protocol_version_from_the_relay(monkeypatch):
    # demo/gonogo.py offers this version in its proxy handshake and refuses any
    # other. A copy of the literal there would send a version the proxy rejects
    # the moment relay.py moves, and print "did not complete a legacy
    # initialize" against a healthy proxy, on a recording day. Patching relay
    # and loading a second copy of the file shows the value flows from relay,
    # which a literal cannot do.
    monkeypatch.setattr(relay, "LEGACY_VERSION", "1999-12-31")
    fresh = load_second_copy(ROOT / "demo" / "gonogo.py", "gonogo_second_copy", monkeypatch)
    assert fresh.LEGACY_VERSION == "1999-12-31"


def test_every_wire_constant_the_fake_server_copies_matches_the_relay():
    # tests/fake_mcp_server.py cannot import cxbom: the proxy copies it into the
    # lock directory and launches it with a scrubbed environment and a bare
    # python3 (proxy_helpers.server_layout), where no cxbom is importable. The
    # copies are deliberate, so this is what keeps them honest. The name list is
    # fixed so a renamed copy shrinks the loop loudly instead of quietly.
    shared = sorted(n for n in vars(fake) if n.isupper() and hasattr(relay, n))
    assert shared == ["LEGACY_VERSION", "META_CLIENT_CAPABILITIES", "META_PROTOCOL_VERSION", "META_SERVER_INFO",
                      "MODERN_VERSION", "UNSUPPORTED_PROTOCOL_VERSION"]
    for name in shared:
        assert getattr(fake, name) == getattr(relay, name), name


def test_a_live_proxy_session_binds_through_session_from_meta(tmp_path):
    setup = signed_setup(tmp_path)
    p = ProxyProcess(setup)
    try:
        p.send(init())
        assert p.recv()["result"]["protocolVersion"] == fake.LEGACY_VERSION
        p.send(note("notifications/initialized"))
        p.send(rpc(2, "tools/list"))
        reply = p.recv()
        while reply is not None and reply.get("id") != 2:
            reply = p.recv()
        assert [t["name"] for t in reply["result"]["tools"]] == ["fetch"]
        session = binding.session_from_meta(reply["result"])
        assert p.close() == 0
    finally:
        if p.proc.poll() is None:
            os.killpg(p.proc.pid, signal.SIGKILL)
            p.proc.wait(timeout=5)
    assert session is not None
    # The emitter names the attestation log after the same id the proxy spliced
    # into _meta, which is what makes a recording attributable to one session.
    assert p.log_path().name == f"fetch-{session.proxy_session_id}.jsonl"


def test_the_proxy_modules_run_without_the_emit_extra():
    code = "import sys, cxbom.cli, cxbom.proxy, cxbom.approve; print('tokenizers' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"


def test_the_installed_console_script_runs_the_cli(built_wheel, tmp_path):
    target = tmp_path / "site"
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--no-index", "--target", str(target),
                    str(built_wheel)], check=True, capture_output=True)
    env = dict(os.environ, PYTHONPATH=str(target))
    script = subprocess.run([str(target / "bin" / "cxbom"), "--help"], cwd=tmp_path, env=env,
                            capture_output=True, text=True)
    assert script.returncode == 0, script.stderr
    assert "not covered in this version (spec 2):" in script.stdout
    module = subprocess.run([sys.executable, "-m", "cxbom", "--help"], cwd=tmp_path, env=env,
                            capture_output=True, text=True)
    assert module.returncode == 0
    assert module.stdout == script.stdout
