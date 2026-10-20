"""Regenerate the C3 example lock, key, and attestation log deterministically.

Owner: ATACE Working Group.

The example key is derived from a fixed seed, so anyone can reproduce the
example byte for byte. It is published and signs nothing real.
Run from the repo root: python contracts/proxy/make_example.py
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sys
# The repo root goes on sys.path so this script runs from any directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cxbom.canonical import object_sha256
from cxbom.signing import encode_pub, fingerprint, sign_envelope

HERE = Path(__file__).resolve().parent
SEED = hashlib.sha256(b"cxbom contract example key v1").digest()
FETCH_SHA = "5aa12876892b083fa01a925df774c715b11a20a3c47164e14b6126e731460dd1"


def example_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEED)


def build() -> tuple[str, str]:
    key = example_key()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    scope = hashlib.sha256(b"cxbom example lock scope").hexdigest()[:32]
    envelope = {
        "serverId": "fetch", "lockScope": scope, "entrySeq": 1,
        "issuedAt": "2026-10-10T18:00:00Z", "notAfter": None,
        "entry": {
            "argv": ["uvx", "mcp-server-fetch==0.0.0"],
            "binary": {"name": "uvx", "sha256": hashlib.sha256(b"example uvx binary").hexdigest()},
            "interpreter": None, "files": {}, "trees": {}, "env": {},
            "firstParty": False, "allowObserve": False, "allowSampling": False, "allowAcceptFlag": False,
            "renderer": "jcs", "clientCapabilitiesSha256": object_sha256({}),
            "eras": {"legacy": {
                "negotiatedVersion": "2025-11-25", "instructionsSha256": object_sha256(""),
                "serverInfo": {"name": "mcp-fetch", "version": "1.0.0"},
                "tools": {"fetch": {"sha256": FETCH_SHA, "approvedAt": "2026-10-10T18:00:00Z",
                                    "approvedBy": "demo-operator", "approvalMode": "interactive",
                                    "reason": "reviewed description and schema"}},
                "prompts": {}, "resources": {}, "resourceTemplates": {}, "ignoreFields": []}}}}
    lock = {"contract": {"name": "cxbom-lock", "version": "2.0.0"},
            "canonicalization": "RFC 8785 JSON Canonicalization Scheme",
            "lockScope": scope,
            "servers": {"fetch": {"envelope": envelope, "signature": sign_envelope(key, envelope)}}}
    return json.dumps(lock, indent=2, sort_keys=True) + "\n", encode_pub(raw) + "\n"


def build_attestation() -> str:
    """The example session log. The server line precedes the verdict line (spec 8.5).

    The envelope hash, key fingerprint, and instructions hash are real values
    from the example lock. The launch hash is a labeled stand-in, because a
    contract example cannot pin a real machine's launch.
    """
    lock_text, _ = build()
    env = json.loads(lock_text)["servers"]["fetch"]["envelope"]
    raw = example_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    lines = [
        {"contract": {"name": "cxbom-attestation", "version": "2.0.0"}, "envelopeSha256": object_sha256(env),
         "keyFingerprint": fingerprint(raw), "kind": "session",
         "launchSha256": hashlib.sha256(b"example launch").hexdigest(), "mode": "enforce", "pid": 4242,
         "proxySessionId": "3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11", "serverId": "fetch",
         "startedAt": "2026-10-10T18:05:00Z"},
        {"at": "2026-10-10T18:05:01Z", "era": "legacy", "kind": "protocol", "protocolVersion": "2025-11-25",
         "seq": 1},
        {"at": "2026-10-10T18:05:01Z", "instructionsSha256": object_sha256(""), "kind": "server", "seq": 2,
         "serverInfo": {"name": "mcp-fetch", "version": "1.0.0"}, "storeRef": None, "verdict": "pinned-match"},
        {"approvalMode": "interactive", "approvedAt": "2026-10-10T18:00:00Z", "approvedBy": "demo-operator",
         "at": "2026-10-10T18:05:02Z", "itemType": "tool", "kind": "verdict", "name": "fetch", "seq": 3,
         "sha256": FETCH_SHA, "storeRef": None, "verdict": "pinned-match"},
        {"at": "2026-10-10T18:07:00Z", "kind": "end", "reason": "eof", "seq": 4}]
    return "".join(json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n" for line in lines)


if __name__ == "__main__":
    lock_text, pub_text = build()
    (HERE / "example.cxbom.lock").write_text(lock_text)
    (HERE / "example-key.pub").write_text(pub_text)
    (HERE / "example.attestation.jsonl").write_text(build_attestation())
