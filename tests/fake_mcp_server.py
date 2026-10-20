"""Scriptable dual-era fake MCP server for proxy, client, and approve tests.

Owner: ATACE Working Group.

The server speaks the legacy era (initialize handshake, 2025-11-25) and the
modern era (stateless requests carrying _meta, server/discover, 2026-07-28).
A script dict drives it. FakeServer.handle() is pure (one input line in, a
list of output lines out), so in-process tests run without a subprocess. The
stdio entry point wraps the same class for end-to-end tests.

This file uses only the standard library, because the proxy launches it with
a scrubbed environment and a bare interpreter.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

# cxbom.relay owns these wire constants. This file cannot import them:
# the proxy launches it as a subprocess with a scrubbed environment and a bare
# python3 from the trusted search path, after copying it into the lock
# directory, so no cxbom is importable there (see proxy_helpers.server_layout).
# tests/test_integration_seams.py holds every copy below equal to relay's, so
# drift fails the suite instead of surfacing as a protocol refusal.
LEGACY_VERSION = "2025-11-25"
MODERN_VERSION = "2026-07-28"
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
UNSUPPORTED_PROTOCOL_VERSION = -32022

FETCH = {"name": "fetch", "description": "Fetches a URL from the internet and extracts its contents as markdown.",
         "inputSchema": {"type": "object"}}

DEFAULTS = {
    "eras": ["legacy"],
    "legacyVersion": LEGACY_VERSION,
    "modernVersions": [MODERN_VERSION],
    "serverInfo": {"name": "fake-mcp", "version": "1.0.0"},
    "instructions": "",
    "tools": [FETCH],
    "pageSize": None,
    "swapAfterList": None,
    "toolsAfter": None,
    "instructionsAfter": None,
    "rawResponses": {},
    "samplingOnCall": None,
    "requireEnv": [],
    "ignoreSigterm": False,
    "spawnGrandchild": False,
    "pidFile": None,
    "envFile": None,
    "ttlMs": None,
    "forgedCxbomMeta": False,
    "exitCodeOnEof": 0,
    "hangOnEof": False,
    "neverReadStdin": False,
    "silent": [],
    "stderrOnStart": None,
    "echoClientInfo": False,
}


def _dump(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


class FakeServer:
    def __init__(self, script: dict | None = None):
        unknown = set(script or {}) - set(DEFAULTS)
        if unknown:
            raise ValueError(f"unknown script keys: {sorted(unknown)}")
        self.s = dict(DEFAULTS, **(script or {}))
        self.tools = list(self.s["tools"])
        self.instructions = self.s["instructions"]
        self.list_responses = 0
        self.raw = {k: list(v) for k, v in self.s["rawResponses"].items()}
        self.received: list[dict] = []
        self.next_server_id = 1

    def _modern_version(self, params: dict) -> str | None:
        meta = params.get("_meta") if isinstance(params, dict) else None
        if isinstance(meta, dict) and isinstance(meta.get(META_PROTOCOL_VERSION), str):
            return meta[META_PROTOCOL_VERSION]
        return None

    def _missing_client_capabilities(self, params: dict) -> bool:
        # A request that names a protocol version is modern-shaped, and a real
        # modern server requires clientCapabilities alongside it. A request
        # naming neither key stays legacy-shaped, so this only fires once the
        # caller already knows _modern_version(params) returned a version.
        meta = params.get("_meta") if isinstance(params, dict) else None
        return not (isinstance(meta, dict) and META_CLIENT_CAPABILITIES in meta)

    def _result(self, rid, result: dict) -> bytes:
        return _dump({"jsonrpc": "2.0", "id": rid, "result": result})

    def _error(self, rid, code: int, message: str, data=None) -> bytes:
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return _dump({"jsonrpc": "2.0", "id": rid, "error": err})

    def _unsupported(self, rid, requested) -> bytes:
        return self._error(rid, UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version",
                           {"supported": self.s["modernVersions"], "requested": requested})

    def _decorate(self, result: dict, modern: bool) -> dict:
        if modern:
            result["resultType"] = "complete"
            if self.s["ttlMs"] is not None:
                result["ttlMs"] = self.s["ttlMs"]
                result["cacheScope"] = "public"
        if self.s["forgedCxbomMeta"]:
            result.setdefault("_meta", {}).update(
                {"org.cxbom/proxySessionId": "forged", "org.cxbom/other": 1, "keep": True})
        return result

    def handle(self, line: bytes) -> list[bytes]:
        try:
            msg = json.loads(line)
        except ValueError:
            return [self._error(None, -32700, "parse error")]
        if not isinstance(msg, dict):
            return [self._error(None, -32600, "batching is not supported")]
        self.received.append(msg)
        method = msg.get("method")
        rid = msg.get("id")
        if method is None or "id" not in msg:
            return []                                  # responses and notifications
        params = msg.get("params") or {}
        if method in self.s["silent"]:
            return []
        if method in self.raw and self.raw[method]:
            raw = bytes.fromhex(self.raw[method].pop(0))
            return [raw.replace(b"__ID__", json.dumps(rid).encode())]
        modern = self._modern_version(params)
        # A fake that never enabled the modern era has nothing to validate
        # against modern-only requirements. It answers as it always did, so
        # a legacy-only fake still reports method-not-found on server/discover
        # rather than a spurious Invalid params.
        if modern is not None and "modern" in self.s["eras"] and self._missing_client_capabilities(params):
            return [self._error(rid, -32602, "Invalid params",
                                {"missing": META_CLIENT_CAPABILITIES})]
        if method == "server/discover":
            if "modern" not in self.s["eras"]:
                return [self._error(rid, -32601, "Method not found")]
            if modern is not None and modern not in self.s["modernVersions"]:
                return [self._unsupported(rid, modern)]
            return [self._result(rid, self._decorate({
                "supportedVersions": self.s["modernVersions"], "capabilities": {"tools": {"listChanged": True}},
                "_meta": {META_SERVER_INFO: self.s["serverInfo"]}, "instructions": self.instructions}, True))]
        if method == "initialize":
            if "legacy" not in self.s["eras"]:
                return [self._error(rid, -32601, "Method not found")]
            result = {
                "protocolVersion": self.s["legacyVersion"],
                "capabilities": {"tools": {"listChanged": True}, "prompts": {}, "resources": {}},
                "serverInfo": self.s["serverInfo"], "instructions": self.instructions}
            # Opt-in echo so a test can confirm which clientInfo the client
            # actually put on the wire, since the server runs in a subprocess.
            if self.s["echoClientInfo"]:
                result["clientInfoEcho"] = params.get("clientInfo")
            return [self._result(rid, self._decorate(result, False))]
        if modern is not None and modern not in self.s["modernVersions"]:
            return [self._unsupported(rid, modern)]
        if method == "ping":
            return [self._result(rid, {})]
        if method == "tools/list":
            return self._tools_list(rid, params, modern is not None)
        if method == "tools/call":
            return self._tools_call(rid, params)
        return [self._error(rid, -32601, "Method not found")]

    def _tools_list(self, rid, params: dict, modern: bool) -> list[bytes]:
        size = self.s["pageSize"]
        cursor = params.get("cursor")
        start = int(cursor[1:]) if isinstance(cursor, str) and cursor.startswith("c") else 0
        end = len(self.tools) if size is None else min(start + size, len(self.tools))
        result = {"tools": self.tools[start:end]}
        if end < len(self.tools):
            result["nextCursor"] = f"c{end}"
        out = [self._result(rid, self._decorate(result, modern))]
        self.list_responses += 1
        if self.s["swapAfterList"] is not None and self.list_responses == self.s["swapAfterList"]:
            if self.s["toolsAfter"] is not None:
                self.tools = list(self.s["toolsAfter"])
            if self.s["instructionsAfter"] is not None:
                self.instructions = self.s["instructionsAfter"]
            out.append(_dump({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}))
        return out

    def _tools_call(self, rid, params: dict) -> list[bytes]:
        name = params.get("name")
        out = []
        if name == self.s["samplingOnCall"]:
            sid = f"srv-{self.next_server_id}"
            self.next_server_id += 1
            out.append(_dump({"jsonrpc": "2.0", "id": sid, "method": "sampling/createMessage",
                              "params": {"messages": [], "maxTokens": 1}}))
        out.append(self._result(rid, {"content": [{"type": "text", "text": f"called {name}"}], "isError": False}))
        return out


def main(argv: list[str]) -> int:
    script = {}
    if len(argv) == 2 and argv[0] == "--script":
        with open(argv[1], encoding="utf-8") as f:
            script = json.load(f)
    server = FakeServer(script)
    if server.s["stderrOnStart"]:
        sys.stderr.write(server.s["stderrOnStart"] + "\n")
        sys.stderr.flush()
    missing = [n for n in server.s["requireEnv"] if n not in os.environ]
    if missing:
        sys.stderr.write(f"fake server: missing environment {missing}\n")
        return 3
    if server.s["ignoreSigterm"]:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    pids = {"pid": os.getpid(), "pgid": os.getpgid(0)}
    if server.s["spawnGrandchild"]:
        grandchild = subprocess.Popen(
            [sys.executable, "-c", "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(600)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pids["grandchild"] = grandchild.pid
    if server.s["pidFile"]:
        with open(server.s["pidFile"], "w", encoding="utf-8") as f:
            json.dump(pids, f)
    if server.s["envFile"]:
        with open(server.s["envFile"], "w", encoding="utf-8") as f:
            json.dump({"env": dict(os.environ), "cwd": os.getcwd()}, f)
    if server.s["neverReadStdin"]:
        # For the writer-overflow test: a child that never drains its stdin
        # pipe forces the proxy's own writer queue to back up deterministically
        # instead of racing against how fast this process happens to read.
        time.sleep(600)
        return 0
    out = sys.stdout.buffer
    for line in sys.stdin.buffer:
        line = line.rstrip(b"\n")
        if not line:
            continue
        for reply in server.handle(line):
            out.write(reply + b"\n")
        out.flush()
    if server.s["hangOnEof"]:
        time.sleep(600)
    return server.s["exitCodeOnEof"]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
