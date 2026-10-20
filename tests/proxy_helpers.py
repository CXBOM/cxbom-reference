"""Shared helpers for launch, proxy, and approve tests. Owner: ATACE Working Group."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FAKE = HERE / "fake_mcp_server.py"


def server_layout(lock_dir: Path, script: dict | None = None) -> tuple[list, dict]:
    """Copy the fake server into lock_dir and return (argv, environ) that launch it.

    argv names files relative to the lock directory, as a signed lock does.
    argv[0] is the bare name "python3". launch.py resolves a bare argv[0]
    only against its own trusted search path, never against environ["PATH"],
    so "python3" resolves the same way here as it does everywhere this suite
    runs: /opt/homebrew/bin/python3 or /usr/local/bin/python3 on macOS, the
    system python3 in CI on ubuntu, and /usr/bin/python3 on the Jetson.
    fake_mcp_server.py uses only the standard library, so whichever python3
    answers still runs it.
    """
    lock_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FAKE, lock_dir / "fake_mcp_server.py")
    (lock_dir / "script.json").write_text(json.dumps(script or {}))
    argv = ["python3", "fake_mcp_server.py", "--script", "script.json"]
    environ = {"LANG": "C.UTF-8", "HOME": str(Path.home())}
    return argv, environ


# ----- in-process cores (added with the intercept core) -------------------------------

import fake_mcp_server as fake  # noqa: E402

from cxbom import attestation, state  # noqa: E402
from cxbom.canonical import instructions_sha256, object_sha256, tool_sha256  # noqa: E402
from cxbom.store import Store  # noqa: E402

T = "2026-10-10T18:00:00Z"
CAPS_SHA = object_sha256({})


def era(tools=(fake.FETCH,), instructions="", version="2025-11-25", mode="interactive", ignore=()):
    return {"negotiatedVersion": version, "instructionsSha256": instructions_sha256(instructions),
            "serverInfo": {"name": "fake-mcp", "version": "1.0.0"},
            "tools": {t["name"]: {"sha256": tool_sha256(t, ignore), "approvedAt": T, "approvedBy": "demo-operator",
                                  "approvalMode": mode, "reason": "reviewed"} for t in tools},
            "prompts": {}, "resources": {}, "resourceTemplates": {},
            "ignoreFields": [{"pointer": p, "reason": "volatile"} for p in ignore]}


def entry(eras=None, **flags):
    e = {"argv": ["python3", "fake_mcp_server.py"], "binary": {"name": "python3", "sha256": "0" * 64},
         "interpreter": None, "files": {}, "trees": {}, "env": {}, "firstParty": False, "allowObserve": False,
         "allowSampling": False, "allowAcceptFlag": False, "renderer": "jcs", "clientCapabilitiesSha256": CAPS_SHA,
         "eras": {"legacy": era()} if eras is None else eras}
    e.update(flags)
    return e


def session(mode="enforce"):
    return {"contract": {"name": "cxbom-attestation", "version": "2.0.0"}, "serverId": "fetch", "mode": mode,
            "startedAt": T, "pid": 1, "envelopeSha256": "a" * 64, "keyFingerprint": "b" * 64,
            "launchSha256": "c" * 64}


class ListEvents:
    """Records what the core emits. of() renders a DescriptionChange the way the sink does,
    with no redaction or scrub, so a test pins the diff text an operator reads."""

    def __init__(self):
        self.items = []

    def emit(self, type_, data):
        self.items.append((type_, data))

    def of(self, type_):
        from cxbom import proxy
        return [{k: proxy.render_description_diff(v) if isinstance(v, proxy.DescriptionChange) else v
                 for k, v in d.items()} for t, d in self.items if t == type_]


def rpc(rid, method, params=None):
    msg = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg).encode()


def note(method, params=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg).encode()


def init(rid=0, caps=None):
    return rpc(rid, "initialize", {"protocolVersion": fake.LEGACY_VERSION, "capabilities": caps or {},
                                   "clientInfo": {"name": "test-client", "version": "0"}})


def modern_meta(version=fake.MODERN_VERSION, caps=None, **extra):
    meta = {fake.META_PROTOCOL_VERSION: version, fake.META_CLIENT_CAPABILITIES: caps or {}}
    meta.update(extra)
    return {"_meta": meta}


class Loop:
    """A core wired to an in-process FakeServer through one queue per direction.

    send() hands the core one client line, then pump() delivers everything
    the core sent to the server and feeds every server reply back, until
    both queues are empty. hold=True leaves server-bound lines queued so a
    test can deliver replies out of order with deliver().
    """

    def __init__(self, tmp_path, entry_, core, script=None, mode="enforce"):
        self.fake = fake.FakeServer(script)
        self.to_server = []
        self.client = []
        self.raw_client = []
        self.events = ListEvents()
        self.now = 0.0
        self.fatal = []
        self.log = attestation.AttestationWriter(tmp_path / "attest", "fetch", session(mode))
        self.core = core(server_id="fetch", mode=mode, entry=entry_, log=self.log, store=Store(tmp_path / "store"),
                        to_client=self._to_client, to_server=self.to_server.append,
                        proxy_session_id=self.log.proxy_session_id, events=self.events,
                        clock=lambda: self.now, on_fatal=self.fatal.append)

    def _to_client(self, line):
        self.raw_client.append(line)
        try:
            self.client.append(json.loads(line))
        except ValueError:
            self.client.append(None)           # observe mode relays unparseable lines as they came

    def send(self, line, hold=False):
        self.core.from_client(line)
        if not hold:
            self.pump()

    def server_says(self, line):
        self.core.from_server(line)
        self.pump()

    def pump(self):
        while self.to_server:
            self.deliver(0)

    def deliver(self, index):
        line = self.to_server.pop(index)
        for out in self.fake.handle(line):
            self.core.from_server(out)

    def take(self):
        out, self.client = self.client, []
        return out

    def lines(self):
        return attestation.read_log(self.log.path)

    def kinds(self):
        return [line["kind"] for line in self.lines()]

    def states(self):
        return state.compute(self.lines())

    def tool_state(self, name):
        return state.lookup(self.states(), "tool", name)

    def handshake(self, caps=None):
        self.send(init(0, caps))
        self.send(note("notifications/initialized"))
        return self.take()


# ----- signed locks and a proxy subprocess (added with proxy.run) ---------------------

import os  # noqa: E402
import queue  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from dataclasses import dataclass  # noqa: E402

from cxbom import launch, lockfile, signing  # noqa: E402
from cxbom.timeutil import now_rfc3339  # noqa: E402

PASS = b"test passphrase"
SCOPE = "ab" * 16


@dataclass
class Setup:
    lock_dir: Path
    argv: list
    environ: dict
    config: Path
    state: Path
    key: object


def signed_setup(tmp_path, script=None, eras=None, seq=1, issued=None, not_after=None, pin_env=(), secret_env=(),
                 extra_env=None, **flags) -> Setup:
    """A lock dir with the fake server, a user key in its own config dir, and a signed lock.

    pin_env, secret_env, and extra_env sign env pins straight into the entry,
    bypassing approve, so a test can present an entry signed under older rules.
    """
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir, script)
    environ.update(extra_env or {})
    config = tmp_path / "config"
    if not (config / signing.KEY_FILE).exists():
        signing.generate_key(PASS, config, now_rfc3339())
    key = signing.load_private(PASS, config)
    ent = entry(eras, **flags)
    ent.update(launch.compute_launch_pins(argv, lock_dir, environ, pin_env, secret_env))
    lock = lockfile.new_lock(SCOPE)
    env = {"serverId": "fetch", "lockScope": SCOPE, "entrySeq": seq, "issuedAt": issued or now_rfc3339(),
           "notAfter": not_after, "entry": ent}
    lock["servers"]["fetch"] = {"envelope": env, "signature": signing.sign_envelope(key, env)}
    lockfile.write_lock(lock_dir / "cxbom.lock", lock)
    return Setup(lock_dir, argv, environ, config, tmp_path / "state", key)


HARNESS = (
    "import json, os, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from pathlib import Path\n"
    "from cxbom import attestation, proxy\n"
    # Test-only fault injection, gated on an env var only this harness ever
    # sets: after the Nth successful attestation write, close the log's
    # real fd out from under it so the (N+1)th write hits a genuine EBADF.
    # cxbom/attestation.py is not touched and has no knowledge of this. The
    # weakening lives entirely here, in test code the shipped proxy never
    # runs (Task 10 review, minor 9).
    "_fail_after = os.environ.get('CXBOM_TEST_BREAK_ATTESTATION_AFTER')\n"
    "if _fail_after is not None:\n"
    "    _n = int(_fail_after)\n"
    "    _orig_raw_write = attestation.AttestationWriter._raw_write\n"
    "    _count = [0]\n"
    "    def _break_after(self, data):\n"
    "        _count[0] += 1\n"
    "        if _count[0] > _n:\n"
    "            try:\n"
    "                os.close(self.fd)\n"
    "            except OSError:\n"
    "                pass\n"
    "            self.fd = -1\n"
    "        return _orig_raw_write(self, data)\n"
    "    attestation.AttestationWriter._raw_write = _break_after\n"
    # Test-only, same gating: the sidecar writer fails to prepare its first
    # N events, so the session drops exactly N through the writer's own
    # failure path and cxbom/proxy.py is not touched.
    "_drop_first = os.environ.get('CXBOM_TEST_DROP_FIRST_EVENTS')\n"
    "if _drop_first is not None:\n"
    "    _left = [int(_drop_first)]\n"
    "    _orig_event_data = proxy._event_data\n"
    "    def _fail_first(*a, **k):\n"
    "        if _left[0] > 0:\n"
    "            _left[0] -= 1\n"
    "            raise ValueError('test: forced drop')\n"
    "        return _orig_event_data(*a, **k)\n"
    "    proxy._event_data = _fail_first\n"
    # Test-only, same gating: the sidecar's first N writes go through, and
    # every later one stalls for 30 s, a disk that stops answering. Only the
    # sidecar's own descriptor is affected.
    "_stall_after = os.environ.get('CXBOM_TEST_STALL_EVENT_WRITES_AFTER')\n"
    "if _stall_after is not None:\n"
    "    import time\n"
    "    _stall = {'left': int(_stall_after), 'fd': None}\n"
    "    _orig_start, _orig_write = proxy.EventSink.start, os.write\n"
    "    def _stall_start(self):\n"
    "        _stall['fd'] = self._fd\n"
    "        return _orig_start(self)\n"
    "    def _stall_write(fd, data):\n"
    "        if fd == _stall['fd']:\n"
    "            if _stall['left'] <= 0:\n"
    "                time.sleep(30)\n"
    "            _stall['left'] -= 1\n"
    "        return _orig_write(fd, data)\n"
    "    proxy.EventSink.start = _stall_start\n"
    "    os.write = _stall_write\n"
    "opts =proxy.ProxyOptions(**json.loads(sys.argv[2]))\n"
    "sys.exit(proxy.run(opts, config_dir=Path(sys.argv[3])))\n")


class ProxyProcess:
    """cxbom proxy in a subprocess, driven as an MCP client would drive it."""

    def __init__(self, setup: Setup, mode="enforce", events=None, redact=(), env=None, state_dir=None, cwd=None,
                 lock=None):
        opts = {"server_id": "fetch", "command": setup.argv, "mode": mode, "lock": lock,
                "state_dir": str(state_dir or setup.state), "events": events, "redact_sha256": list(redact)}
        full_env = dict(os.environ)
        full_env.update(setup.environ)
        full_env.update(env or {})
        self.setup = setup
        self.proc = subprocess.Popen([sys.executable, "-c", HARNESS, str(ROOT), json.dumps(opts), str(setup.config)],
                                     cwd=cwd or setup.lock_dir, env=full_env, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self._lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def send(self, line: bytes) -> None:
        self.proc.stdin.write(line + b"\n")
        self.proc.stdin.flush()

    def recv(self, timeout=10.0):
        line = self._lines.get(timeout=timeout)
        return None if line is None else json.loads(line)

    def close(self, timeout=15.0) -> int:
        self.proc.stdin.close()
        return self.proc.wait(timeout)

    def stderr(self) -> str:
        return self.proc.stderr.read().decode("utf-8", "replace")

    def log_path(self) -> Path:
        (path,) = (self.setup.state / "attest").glob("fetch-*.jsonl")
        return path

    def wait_for_log(self, timeout=10.0) -> Path:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = list((self.setup.state / "attest").glob("fetch-*.jsonl")) if (self.setup.state / "attest").exists() else []
            if found:
                return found[0]
            time.sleep(0.02)
        raise AssertionError("the proxy never opened its attestation log")


def run_refused(setup: Setup, mode="enforce", env=None, state_dir=None, events=None):
    p = ProxyProcess(setup, mode=mode, env=env, state_dir=state_dir, events=events)
    code = p.close()
    return code, p.stderr()


# ----- approve (added with approve.py) --------------------------------------------------

import io  # noqa: E402

from cxbom import approve as approve_mod  # noqa: E402

FETCH_SHA = tool_sha256(fake.FETCH)
EMPTY_INSTRUCTIONS_SHA = instructions_sha256("")
ACCEPT_FETCH = {FETCH_SHA: "reviewed the fetch tool", EMPTY_INSTRUCTIONS_SHA: "no instructions"}


def project(tmp_path, script=None) -> Setup:
    """A lock dir with the fake server and an initialized, empty lock, plus a user key."""
    lock_dir = tmp_path / "proj"
    argv, environ = server_layout(lock_dir, script)
    config = tmp_path / "config"
    if not (config / signing.KEY_FILE).exists():
        signing.generate_key(PASS, config, now_rfc3339())
    if not (lock_dir / "cxbom.lock").exists():
        lockfile.write_lock(lock_dir / "cxbom.lock", lockfile.new_lock(SCOPE))
    return Setup(lock_dir, argv, environ, config, tmp_path / "state", signing.load_private(PASS, config))


def approve(setup: Setup, accept=None, confirm="fetch", passphrase=PASS, env=None, **kw) -> tuple:
    out = io.StringIO()
    opts = approve_mod.ApproveOptions(server_id="fetch", approver="demo-operator", command=list(setup.argv),
                                      accept=dict(ACCEPT_FETCH if accept is None else accept), **kw)
    environ = dict(os.environ)
    environ.update(setup.environ)
    environ.update(env or {})
    code = approve_mod.run(opts, confirm=lambda prompt: confirm, passphrase=lambda: passphrase, out=out,
                           config_dir=setup.config, state_dir=setup.state, environ=environ, cwd=setup.lock_dir)
    return code, out.getvalue()


def read_entry(setup: Setup) -> dict:
    return json.loads((setup.lock_dir / "cxbom.lock").read_text())["servers"]["fetch"]["envelope"]
