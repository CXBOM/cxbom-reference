"""The pure record builder over resolved facts (spec 9.4). Owner: ATACE Working Group."""
import re
from pathlib import Path

import pytest

from cxbom import conformance, consistency
from cxbom.emitter import (GLOSSARY_FIXED, NOT_COLLECTED, BlockedItem, ComponentFacts, RecordInputs, ScanResult,
                           build_record)

DESIGN_DOC = Path(__file__).resolve().parent.parent / "docs" / "design" / "tool.md"

NOW = "2026-10-10T18:06:00Z"
SHA = "a" * 64
MODEL = {"family": "phi", "version": "Phi-3.5-mini-instruct", "provider": "Microsoft", "contextWindowMaxTokens": 131072,
         "architectureType": "transformer-decoder"}
AGENT = {"id": "demo-agent", "name": "Demo agent", "version": "1.0", "operator": "example-org",
         "deploymentEnvironment": "testing", "deploymentId": "deploy-demo"}
TRUST = {"description": "rings", "rings": [
    {"ring": 0, "designation": "operator", "description": "o", "controlLayer": "system-prompt",
     "integrityRequirement": "cryptographic", "allowedSources": [], "externalSourcesPermitted": False}]}
LAYERS = [{"layerId": "tool-execution", "designation": "Tool Execution", "description": "proxy",
           "owaspCoverage": ["LLM04"], "controlsActive": [], "controlsInactive": [], "status": "active",
           "coverageGaps": []}]
GLOSSARY = dict(GLOSSARY_FIXED, **{"content.tokenCount": "tokenizer sha256 x, mode ids"})


def system(**kw):
    base = dict(cid="cc-001", type="system-prompt", subtype="primary-operator-instruction", ring=0, tier="operator",
                layer="system-prompt", label="Operator system prompt", turn=0, position="prepended",
                by_type="systemPrompt", text_sha256=SHA, token_count=30,
                source={"origin": "operator", "thirdParty": False, "operatorControlled": True})
    base.update(kw)
    return ComponentFacts(**base)


def tool(verified: bool, **kw):
    src = {"origin": "mcp-server", "thirdParty": True, "operatorControlled": False, "serverVersionPinned": True,
           "serverChecksumVerified": verified}
    if verified:
        src.update(serverChecksum=SHA, sessionId="s1", uri="cxbom-attest:s1#3", retrievedAt=NOW,
                   authorizedBy="unverified-approver:demo-operator:interactive:signer-0123456789abcdef",
                   serverVersion="1.0.0")
    base = dict(cid="cc-002", type="tool-definition", subtype="external-mcp-server", ring=1, tier="agent",
                layer="tool-execution", label="mcp-tool:fetch/fetch", turn=0, position="tool-schema-block",
                by_type="toolDefinition", text_sha256=SHA, token_count=70, source=src, is_tool=True,
                verified=verified, unbound_cause="" if verified else "no-session",
                source_uri="cxbom-attest:s1#3" if verified else "")
    base.update(kw)
    return ComponentFacts(**base)


def inputs(components, **kw):
    base = dict(session_id="sess-042", turn=1, inference_index=0, model=MODEL, agent=AGENT, trust_model=TRUST,
                control_layers=LAYERS, components=components, overhead_tokens=5, context_window_max=131072,
                glossary=GLOSSARY)
    base.update(kw)
    return RecordInputs(**base)


def valid(doc):
    return conformance.check_all(doc) + consistency.check(doc)


def test_verified_tool_record():
    doc = build_record(inputs([system(), tool(True)]), NOW)
    assert valid(doc) == []
    comp = doc["contextComponents"][1]
    assert comp["source"]["serverChecksumVerified"] is True
    assert comp["toolDefinitionTrustInversion"]["detected"] is True
    assert comp["toolDefinitionTrustInversion"]["mitigationStatus"] == "none"
    cats = [f["category"] for f in doc["findings"]]
    assert cats == ["trust-inversion", "missing-control", "missing-control", "missing-control"]
    ss = doc["sessionSummary"]
    assert (ss["totalContextTokens"], ss["templateOverheadTokens"]) == (100, 5)
    assert doc["metadata"]["session"]["contextWindowTokensUsed"] == 105
    assert doc["metadata"]["session"]["id"] == "sess-042/1/0"
    assert ss["auditTrailComplete"] is True and ss["sessionAuditClean"] is False
    assert sorted(ss["auditCleanBlockers"]) == [f["id"] for f in doc["findings"]]
    assert comp["notCollected"] == list(NOT_COLLECTED)


def test_unverified_tool_gets_one_binding_finding():
    doc = build_record(inputs([system(), tool(False)]), NOW)
    assert valid(doc) == []
    cats = [f["category"] for f in doc["findings"] if "cc-002" in f["affectedComponents"]]
    assert cats.count("tool-definition-binding") == 1
    assert doc["sessionSummary"]["auditTrailComplete"] is False


def test_verified_tool_may_decline_server_version():
    """Ledger ruling (Task 8, applied Task 9): a live server that never reports
    its own version (Binding.server_version is None) omits source.serverVersion
    and lists it in notCollected instead of inventing a value. Both the
    vendored validator and consistency.check must accept that form on an
    otherwise fully verified, schema-valid record."""
    doc = build_record(inputs([system(), tool(True)]), NOW)
    comp = doc["contextComponents"][1]
    del comp["source"]["serverVersion"]
    comp["notCollected"] = comp.get("notCollected", []) + ["source.serverVersion"]
    assert valid(doc) == []


def test_changed_tool_gets_a_change_finding_instead():
    doc = build_record(inputs([system(), tool(False, changed=True)]), NOW)
    assert valid(doc) == []
    cats = [f["category"] for f in doc["findings"]]
    assert "tool-definition-change" in cats and "tool-definition-binding" not in cats


def test_blocked_item_is_mitigated_and_not_a_blocker():
    doc = build_record(inputs([system()], blocked=[BlockedItem("fetch", "fetch", "changed", "cxbom-attest:s1#4")]),
                       NOW)
    assert valid(doc) == []
    blocked = [f for f in doc["findings"] if f["category"] == "tool-definition-blocked"]
    assert blocked[0]["status"] == "mitigated" and blocked[0]["id"] not in doc["sessionSummary"]["auditCleanBlockers"]


def test_scanned_record_can_be_clean():
    scan = ScanResult("demo-scanner", "1.0", NOW, "clean", "low", False, False, False)
    doc = build_record(inputs([system(scan=scan)]), NOW)
    assert valid(doc) == []
    assert doc["findings"] == [] and doc["sessionSummary"]["sessionAuditClean"] is True
    assert "notCollected" not in doc["contextComponents"][0]


def test_special_tokens_flag_and_find():
    doc = build_record(inputs([system(special_role=("<|system|>",), special_other=("<s>",))]), NOW)
    assert valid(doc) == []
    comp = doc["contextComponents"][0]
    assert comp["auditFlags"] == ["SPECIAL_TOKEN_IN_CONTENT"]
    sev = sorted(f["severity"] for f in doc["findings"] if f["category"] == "special-token-injection")
    assert sev == ["high", "medium"]


def test_model_output_buckets_as_model_output():
    out = system(cid="cc-003", type="retrieved-document", subtype="memory-injection", ring=1, tier="ring-1-derived",
                 layer="reasoning", label="Model output, turn 1", turn=1, position="model-output-turn-1",
                 by_type="modelOutput", source={"origin": "model-generated", "thirdParty": False})
    doc = build_record(inputs([system(), out]), NOW)
    assert valid(doc) == []
    assert doc["sessionSummary"]["componentBreakdown"]["byType"]["modelOutput"]["tokens"] == 30


def test_timestamp_yesterday_fails_the_validator():
    doc = build_record(inputs([system()]), NOW)
    doc["metadata"]["timestamp"] = "yesterday"
    assert conformance.check_all(doc) != []


@pytest.mark.parametrize("count", [1, 3, 7])
def test_shares_follow_the_validator_rounding(count):
    comps = [system(cid=f"cc-{i:03d}", token_count=i + 1) for i in range(1, count + 1)]
    assert valid(build_record(inputs(comps), NOW)) == []


def _glossary_table_from_docs() -> dict[str, str]:
    """Parse the fixed-text "Field | Entry" table under spec 9.4's "Glossary
    entries" heading in docs/design/tool.md. Backticks are markdown-only
    (`content.tokenCount` is inline-coded in the doc), and GLOSSARY_FIXED stores
    plain text, so they are stripped before comparison."""
    text = DESIGN_DOC.read_text(encoding="utf-8")
    section = text[text.index("**Glossary entries**"):]
    table: dict[str, str] = {}
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            if table:
                break  # the table ended, so stop before the bullet list that follows it
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 2:
            continue
        field, entry = (c.replace("`", "").strip() for c in cells)
        if field == "Field" or re.fullmatch(r"-+", field):
            continue  # header or separator row
        table[field] = entry
    return table


def test_glossary_fixed_matches_spec_94_table():
    # A wording change to a glossary entry changes what the record claims about
    # itself, so it must be a deliberate edit to the spec table, not a drift.
    table = _glossary_table_from_docs()
    checked = {k: v for k, v in table.items() if k != "content.tokenCount"}
    assert checked, "failed to parse the spec 9.4 glossary table"
    # content.tokenCount documents a field the record carries, not a fixed string
    # the emitter writes, so it has a doc row and no code entry. The exclusion is
    # one-sided on purpose and asserted rather than assumed: if the key ever
    # enters GLOSSARY_FIXED, the equality below would fail for a reason its
    # message cannot explain, so it fails here with one that can.
    assert "content.tokenCount" not in GLOSSARY_FIXED, (
        "content.tokenCount is now a fixed glossary entry, so drop it from the doc-side "
        "exclusion above and let both sides be compared.")
    # Key-set equality, not "every doc row is in the code": that direction alone
    # goes quiet when a doc row is deleted, because the loop then has one fewer
    # thing to look for, and it never looks at a key the code carries with no
    # doc row at all. Both were verified dead against the full suite before
    # this line existed. Every entry is text the record prints about itself, so
    # an undocumented one is a claim no spec table stands behind.
    assert set(checked) == set(GLOSSARY_FIXED), set(checked) ^ set(GLOSSARY_FIXED)
    for key, expected in checked.items():
        assert GLOSSARY_FIXED.get(key) == expected, key


def test_build_record_rejects_is_tool_type_mismatch():
    bad = system(cid="cc-002", is_tool=True)
    with pytest.raises(ValueError):
        build_record(inputs([system(), bad]), NOW)


def test_build_record_rejects_verified_without_checksum_claim():
    bad = system(cid="cc-002", verified=True)
    with pytest.raises(ValueError):
        build_record(inputs([system(), bad]), NOW)


def test_build_record_rejects_no_components():
    with pytest.raises(ValueError):
        build_record(inputs([]), NOW)


def test_build_record_rejects_zero_total_tokens():
    with pytest.raises(ValueError):
        build_record(inputs([system(token_count=0)]), NOW)


def test_build_record_rejects_ring_out_of_range():
    with pytest.raises(ValueError):
        build_record(inputs([system(ring=3)]), NOW)


def test_build_record_rejects_used_tokens_over_context_window():
    with pytest.raises(ValueError):
        build_record(inputs([system(token_count=200_000)], context_window_max=131072), NOW)
