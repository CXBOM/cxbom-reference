"""Assembly facts to a CxBOM 0.3.0 record (spec 9.4 and 10).

Owner: ATACE Working Group.

build_record is a pure function over facts the Assembly already resolved. It
writes existing 0.3.0 fields only. Everything 0.3.0 cannot say (the tokenizer
pin, the binding semantics, the model revision) goes into
schema.fieldGlossary. Integrity never touches the trust-inversion
mitigationStatus: the vendored detector decides inversion from structure
alone, and integrity shows up only in serverChecksumVerified.
"""
from __future__ import annotations

import decimal
import json
import uuid
from dataclasses import dataclass, field

from . import __version__, crosswalk, findings
from .detectors import detect_trust_inversion

SCHEMA_URL = "https://cxbom.org/schema/0.3.0/cxbom.schema.json"
NOT_COLLECTED = ("injectionRiskRating", "sanitization.scanner", "sanitization.scannerVersion",
                 "sanitization.scannedAt", "containsPII", "containsCredentials", "containsSecretsOrKeys")
MISSING_CONTROLS = ["injection-pattern-scan", "pii-scan", "credential-scan"]
_SEVERITY_ORDER = ("critical", "high", "medium", "low")
_RING_KEY = {0: "ring0", 1: "ring1", 2: "ring2"}
_CATALOG_FILES = {"owaspLlm": ("owasp-llm-2026.json", "2026"), "owaspAgentic": ("owasp-asi-2026.json", "2026"),
                  "cwe": ("cwe.json", "CWE"), "atlas": ("atlas.json", "ATLAS")}

GLOSSARY_FIXED = {
    "source.serverChecksumVerified": (
        "Definition hash matched a signed pin in a live, bound proxy session. Server code and dependencies "
        "are not verified. The attestation log is integrity-checked, not authenticated, against same-user "
        "processes"),
    "source.authorizedBy": (
        "Approver role, approval mode, and the fingerprint of the signing key. Not an authenticated person"),
    "content.contextualSharePercent": "Share of component tokens, excluding template overhead. Not a model-weight share",
    "metadata.session.id": (
        "<session_id>/<turn>/<inference_index>. One record per inference. contextWindowTokensUsed, startedAt, "
        "and endedAt are per inference"),
    "sessionSummary.sessionAuditClean": "False unless a scanner callback filled every security field",
    "byType.modelOutput": (
        "Model-generated re-entrant content (ring-1-derived), recorded as retrieved-document or "
        "memory-injection under the frozen enum"),
    # consistency.check requires this key on every record: mitigationStatus "full" needs a
    # registered trust label, and the glossary is where 0.3.0 documents what that label means.
    # Fixed text, spec 9.4: the label changes assembly structure, not model weighting or
    # exploitation, which the spec deliberately does not claim.
    "sanitization.trustLabel": "Registered boundary id. Changes assembly structure, not model weighting",
    # Spec 9.4: a server reports its own version, so the record must say the value is unauthenticated
    # and that serverVersionPinned speaks to the launcher's package argument instead.
    "source.serverVersion": (
        "Server self-reported and not authenticated. serverVersionPinned refers to the launcher's package "
        "argument, not to this value"),
}


@dataclass(frozen=True)
class ScanResult:
    scanner: str
    scanner_version: str
    scanned_at: str
    status: str
    injection_risk_rating: str
    contains_pii: bool
    contains_credentials: bool
    contains_secrets_or_keys: bool


@dataclass(frozen=True)
class ComponentFacts:
    cid: str
    type: str
    subtype: str
    ring: int
    tier: str
    layer: str
    label: str
    turn: int
    position: str
    by_type: str
    text_sha256: str
    token_count: int
    source: dict
    is_tool: bool = False
    verified: bool = False
    changed: bool = False
    unbound_cause: str = ""
    source_uri: str = ""
    special_role: tuple[str, ...] = ()
    special_other: tuple[str, ...] = ()
    # Per rank, the flagged tokens the text spells and the ids do not carry.
    role_spelled: tuple[str, ...] = ()
    other_spelled: tuple[str, ...] = ()
    scan: ScanResult | None = None


@dataclass(frozen=True)
class BlockedItem:
    server_id: str
    name: str
    verdict: str
    source_uri: str


@dataclass(frozen=True)
class RecordInputs:
    session_id: str
    turn: int
    inference_index: int
    model: dict
    agent: dict
    trust_model: dict
    control_layers: list
    components: list
    overhead_tokens: int
    context_window_max: int
    glossary: dict
    blocked: list = field(default_factory=list)


def r2(x) -> float:
    return float(decimal.Decimal(str(x)).quantize(decimal.Decimal("0.01"), rounding=decimal.ROUND_HALF_EVEN))


def catalog_versions() -> dict:
    sources = {e["file"]: e for e in json.loads((crosswalk._CAT / "SOURCES.json").read_text(encoding="utf-8"))}
    out = {}
    for key, (fname, version) in _CATALOG_FILES.items():
        e = sources[fname]
        pin = {"version": version, "url": e["url"], "released": e["released"], "releaseTag": e["releaseTag"],
               "contentHash": e["sha256"]}
        for k in ("commit", "ref"):
            if e.get(k) is not None:
                pin[k] = e[k]
        out[key] = pin
    out["cyclonedx"] = {"version": "1.6", "url": "https://cyclonedx.org/schema/bom-1.6.schema.json"}
    return out


def _component(c: ComponentFacts, total: int) -> dict:
    content = {"sha256": c.text_sha256, "tokenCount": c.token_count,
               "contextualSharePercent": r2(c.token_count / total * 100), "positionInContext": c.position,
               "encodingState": "utf-8", "normalizationApplied": False}
    if c.scan is None:
        sanitization = {"status": "not-assessed", "appliedControls": [], "missingControls": list(MISSING_CONTROLS)}
        rating = "not-assessed"
    else:
        sanitization = {"status": c.scan.status, "appliedControls": [f"scanner:{c.scan.scanner}"],
                        "missingControls": [], "scanner": c.scan.scanner,
                        "scannerVersion": c.scan.scanner_version, "scannedAt": c.scan.scanned_at}
        rating = c.scan.injection_risk_rating
        content.update(containsPII=c.scan.contains_pii, containsCredentials=c.scan.contains_credentials,
                       containsSecretsOrKeys=c.scan.contains_secrets_or_keys)
    comp = {"id": c.cid, "type": c.type, "subtype": c.subtype, "trustRing": c.ring, "trustTier": c.tier,
            "controlLayer": c.layer, "label": c.label, "assembledAtTurn": c.turn, "source": dict(c.source),
            "content": content, "sanitization": sanitization,
            "permissions": {"permittedActions": [], "deniedActions": []},
            "auditFlags": [], "injectionRiskRating": rating, "findingRefs": []}
    not_collected = list(NOT_COLLECTED) if c.scan is None else []
    # Ledger ruling (Task 8, wired here at Task 10): a live server that never
    # reports its own version leaves source.serverVersion out rather than
    # inventing one. notCollected is 0.2.0's own way to say "not asserted", and
    # consistency.check requires exactly this pairing on a verified binding
    # (spec 9.4). This is independent of whether a scanner ran.
    if c.type == "tool-definition" and c.source.get("serverChecksumVerified") is True and \
            "serverVersion" not in c.source:
        not_collected.append("source.serverVersion")
    if not_collected:
        comp["notCollected"] = not_collected
    return comp


def _findings(inp: RecordInputs, comps: list[dict], at: str) -> list[dict]:
    out: list[dict] = []

    def fid() -> str:
        return f"finding-{len(out) + 1:03d}"

    for facts, comp in zip(inp.components, comps):
        if facts.type == "tool-definition":
            tdi = detect_trust_inversion(comp)
            comp["toolDefinitionTrustInversion"] = tdi
            if tdi["detected"]:
                comp["auditFlags"].append("TRUST_INVERSION_DETECTED")
                out.append(findings.trust_inversion(fid(), facts.cid, facts.source_uri, tdi, at))
        if facts.is_tool and not facts.verified:
            if facts.changed:
                out.append(findings.definition_changed(fid(), facts.cid, facts.source_uri, at))
            else:
                out.append(findings.binding_failed(fid(), facts.cid, facts.source_uri, facts.unbound_cause, at))
        if facts.special_role or facts.special_other:
            comp["auditFlags"].append("SPECIAL_TOKEN_IN_CONTENT")
        if facts.special_role:
            out.append(findings.special_token(fid(), facts.cid, facts.layer, True, list(facts.special_role), at,
                                              spelled=list(facts.role_spelled)))
        if facts.special_other:
            out.append(findings.special_token(fid(), facts.cid, facts.layer, False, list(facts.special_other), at,
                                              spelled=list(facts.other_spelled)))
    for item in inp.blocked:
        out.append(findings.definition_blocked(fid(), item.server_id, item.name, item.verdict, item.source_uri, at))
    unscanned = [(f.cid, f.layer) for f in inp.components if f.scan is None]
    if unscanned:
        ids = [cid for cid, _ in unscanned]
        layers = sorted({layer for _, layer in unscanned})
        for group in ("injection", "pii", "credentials"):
            out.append(findings.missing_control(fid(), group, ids, layers, at))
    for comp in comps:
        comp["findingRefs"] = [f["id"] for f in out if comp["id"] in f["affectedComponents"]]
    return out


def _validate_facts(inp: RecordInputs, total: int) -> None:
    """Refuse facts the builder cannot honestly render, before it renders them.

    build_record trusts its facts (it is a pure function, not a re-verifier of
    the assembly), but a caller bug that hands it self-contradictory or
    physically impossible facts must fail loud here, not silently mislabel a
    record downstream. No path or filesystem detail belongs in these
    messages, and a component id is not a path.
    """
    if not inp.components:
        raise ValueError("build_record needs at least one component")
    if total == 0:
        raise ValueError("build_record needs a nonzero total token count")
    for c in inp.components:
        if c.is_tool != (c.type == "tool-definition"):
            raise ValueError(f"{c.cid}: is_tool must agree with type == 'tool-definition'")
        if c.verified != (c.source.get("serverChecksumVerified") is True):
            raise ValueError(f"{c.cid}: verified must agree with source.serverChecksumVerified")
        if c.ring not in (0, 1, 2):
            raise ValueError(f"{c.cid}: trust ring must be 0, 1, or 2, got {c.ring!r}")
    used = total + inp.overhead_tokens
    if used > inp.context_window_max:
        raise ValueError(f"used tokens {used} exceed the context window {inp.context_window_max}")


def build_record(inp: RecordInputs, now: str) -> dict:
    total = sum(c.token_count for c in inp.components)
    _validate_facts(inp, total)
    comps = [_component(c, total) for c in inp.components]
    found = _findings(inp, comps, now)
    ring_tokens = {0: 0, 1: 0, 2: 0}
    ring_ids: dict[int, list[str]] = {0: [], 1: [], 2: []}
    type_tokens: dict[str, int] = {}
    for c in inp.components:
        ring_tokens[c.ring] += c.token_count
        ring_ids[c.ring].append(c.cid)
        type_tokens[c.by_type] = type_tokens.get(c.by_type, 0) + c.token_count
    used = total + inp.overhead_tokens
    open_ids = [f["id"] for f in found if f["status"] == "open"]
    summary = {s: sum(1 for f in found if f["severity"] == s) for s in _SEVERITY_ORDER}
    summary["totalOpen"] = len(open_ids)
    worst = next((s for s in _SEVERITY_ORDER if any(f["severity"] == s and f["status"] == "open" for f in found)),
                 None)
    unverified_tool = any(c.is_tool and not c.verified for c in inp.components)
    layers = inp.control_layers
    return {
        "bomFormat": "CxBOM",
        "specVersion": "0.3.0",
        "illustrative": False,
        "extends": {"format": "CycloneDX", "version": "1.6",
                    "schema": "https://cyclonedx.org/schema/bom-1.6.schema.json"},
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "generatedBy": {"name": "cxbom", "version": __version__, "schema": SCHEMA_URL},
            "session": {
                "id": f"{inp.session_id}/{inp.turn}/{inp.inference_index}",
                "model": inp.model,
                "contextWindowTokensUsed": used,
                "contextWindowUtilizationPercent": r2(used / inp.context_window_max * 100),
                "turnCount": inp.turn,
                "startedAt": now,
                "endedAt": now,
            },
            "agent": inp.agent,
        },
        "trustModel": inp.trust_model,
        "contextComponents": comps,
        "controlLayers": layers,
        "findings": found,
        "sessionSummary": {
            "totalContextTokens": total,
            "templateOverheadTokens": inp.overhead_tokens,
            "componentBreakdown": {
                "byTrustRing": {_RING_KEY[r]: {"tokens": ring_tokens[r], "sharePercent": r2(ring_tokens[r] / total * 100),
                                               "components": ring_ids[r]} for r in (0, 1, 2)},
                "byType": {k: {"tokens": v, "sharePercent": r2(v / total * 100)} for k, v in type_tokens.items()},
            },
            "findingsSummary": summary,
            "controlLayerStatus": {s: [layer["layerId"] for layer in layers if layer["status"] == s]
                                   for s in ("active", "partial", "inactive")},
            "overallRiskRating": worst or "not-assessed",
            "riskRationale": (f"Highest open finding severity is {worst} ({len(open_ids)} open)." if worst
                              else "No open findings. The emitter does not assess residual risk."),
            "auditTrailComplete": not unverified_tool,
            "sessionAuditClean": not open_ids,
            "auditCleanBlockers": open_ids,
        },
        "schema": {"cxbomVersion": "0.3.0", "fieldGlossary": dict(inp.glossary)},
        "catalogVersions": catalog_versions(),
    }
