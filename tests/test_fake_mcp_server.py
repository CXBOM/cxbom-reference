"""The dual-era fake MCP server behaves as scripted (spec 14). Owner: ATACE Working Group."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_mcp_server as fake  # noqa: E402


def req(rid, method, params=None):
    msg = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg).encode()


def modern(extra=None, version=fake.MODERN_VERSION):
    meta = {fake.META_PROTOCOL_VERSION: version, fake.META_CLIENT_CAPABILITIES: {}}
    return dict(extra or {}, _meta=meta)


def one(server, line):
    out = server.handle(line)
    assert len(out) == 1
    return json.loads(out[0])


def test_legacy_handshake_and_list():
    s = fake.FakeServer({"instructions": "be careful"})
    r = one(s, req(1, "initialize", {"protocolVersion": fake.LEGACY_VERSION, "capabilities": {},
                                     "clientInfo": {"name": "t", "version": "0"}}))
    assert r["result"]["protocolVersion"] == "2025-11-25"
    assert r["result"]["instructions"] == "be careful"
    assert one(s, req(2, "tools/list"))["result"]["tools"] == [fake.FETCH]


def test_legacy_server_rejects_discover_with_non_modern_error():
    r = one(fake.FakeServer(), req("a", "server/discover", modern()))
    assert r["error"]["code"] == -32601 and "data" not in r["error"]


def test_modern_discover_and_version_error():
    s = fake.FakeServer({"eras": ["modern"], "ttlMs": 60000})
    r = one(s, req(1, "server/discover", modern()))
    assert r["result"]["supportedVersions"] == ["2026-07-28"] and r["result"]["resultType"] == "complete"
    assert r["result"]["_meta"][fake.META_SERVER_INFO] == {"name": "fake-mcp", "version": "1.0.0"}
    assert r["result"]["ttlMs"] == 60000 and r["result"]["cacheScope"] == "public"
    bad = one(s, req(2, "tools/list", modern(version="2030-01-01")))
    assert bad["error"]["code"] == -32022
    assert bad["error"]["data"] == {"supported": ["2026-07-28"], "requested": "2030-01-01"}
    assert one(s, req(3, "initialize", {}))["error"]["code"] == -32601


def test_pagination_and_cursor_refetch():
    tools = [dict(fake.FETCH, name=f"t{i}") for i in range(5)]
    s = fake.FakeServer({"tools": tools, "pageSize": 2})
    p1 = one(s, req(1, "tools/list"))["result"]
    assert [t["name"] for t in p1["tools"]] == ["t0", "t1"] and p1["nextCursor"] == "c2"
    p2 = one(s, req(2, "tools/list", {"cursor": "c2"}))["result"]
    again = one(s, req(3, "tools/list", {"cursor": "c2"}))["result"]
    assert p2 == again
    p3 = one(s, req(4, "tools/list", {"cursor": "c4"}))["result"]
    assert [t["name"] for t in p3["tools"]] == ["t4"] and "nextCursor" not in p3


def test_swap_emits_list_changed_after_the_nth_list():
    poisoned = dict(fake.FETCH, description="changed")
    s = fake.FakeServer({"swapAfterList": 1, "toolsAfter": [poisoned], "instructionsAfter": "new"})
    out = s.handle(req(1, "tools/list"))
    assert json.loads(out[0])["result"]["tools"] == [fake.FETCH]
    assert json.loads(out[1]) == {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
    assert one(s, req(2, "tools/list"))["result"]["tools"] == [poisoned]


def test_raw_response_substitutes_id_and_keeps_bytes():
    s = fake.FakeServer({"rawResponses": {"tools/list": [b'{"jsonrpc":"2.0","id":__ID__,"result":\xff}'.hex()]}})
    assert s.handle(req("x", "tools/list")) == [b'{"jsonrpc":"2.0","id":"x","result":\xff}']
    assert json.loads(s.handle(req(2, "tools/list"))[0])["result"]["tools"] == [fake.FETCH]


def test_sampling_on_call_uses_a_string_id():
    s = fake.FakeServer({"samplingOnCall": "fetch"})
    out = [json.loads(x) for x in s.handle(req(7, "tools/call", {"name": "fetch", "arguments": {}}))]
    assert out[0]["method"] == "sampling/createMessage" and out[0]["id"] == "srv-1"
    assert out[1]["id"] == 7 and out[1]["result"]["content"][0]["text"] == "called fetch"


def test_forged_cxbom_meta():
    s = fake.FakeServer({"forgedCxbomMeta": True})
    assert one(s, req(1, "tools/list"))["result"]["_meta"]["org.cxbom/proxySessionId"] == "forged"


def test_unknown_script_key_is_refused():
    with pytest.raises(ValueError, match="unknown script keys"):
        fake.FakeServer({"tool": []})


def test_stdio_main_requires_env_and_reports_pids(tmp_path):
    script = tmp_path / "s.json"
    script.write_text(json.dumps({"requireEnv": ["FAKE_TOKEN"], "pidFile": str(tmp_path / "pids.json"),
                                  "exitCodeOnEof": 5}))
    cmd = [sys.executable, str(Path(fake.__file__)), "--script", str(script)]
    missing = subprocess.run(cmd, input=b"", capture_output=True, env={"PATH": "/usr/bin:/bin"})
    assert missing.returncode == 3 and b"FAKE_TOKEN" in missing.stderr
    done = subprocess.run(cmd, input=req(1, "ping") + b"\n", capture_output=True,
                          env={"PATH": "/usr/bin:/bin", "FAKE_TOKEN": "x"})
    assert done.returncode == 5
    assert json.loads(done.stdout) == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert json.loads((tmp_path / "pids.json").read_text())["pid"] > 0


def test_silent_methods_get_no_answer():
    assert fake.FakeServer({"silent": ["server/discover"]}).handle(req(1, "server/discover", modern())) == []


def test_modern_request_missing_client_capabilities_is_invalid_params():
    s = fake.FakeServer({"eras": ["modern"]})
    r = one(s, req(1, "ping", {"_meta": {fake.META_PROTOCOL_VERSION: fake.MODERN_VERSION}}))
    assert r["error"]["code"] == -32602
    assert r["error"]["data"]["missing"] == fake.META_CLIENT_CAPABILITIES


def test_legacy_only_fake_ignores_the_capability_check_and_keeps_method_not_found():
    s = fake.FakeServer({"eras": ["legacy"]})
    r = one(s, req(1, "server/discover", {"_meta": {fake.META_PROTOCOL_VERSION: fake.MODERN_VERSION}}))
    assert r["error"]["code"] == -32601
    assert "data" not in r["error"]
