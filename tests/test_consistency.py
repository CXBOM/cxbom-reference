"""Tool-side meaning checks (spec 9.4 audit summary and integrity rules). Owner: ATACE Working Group."""
import copy

import pytest

from cxbom import consistency

SHA = "a" * 64
BINDING = {"serverChecksumVerified": True, "serverChecksum": SHA, "sessionId": "s1", "uri": "cxbom-attest:s1#3",
           "retrievedAt": "2026-10-10T18:05:00Z",
           "authorizedBy": "unverified-approver:demo-operator:interactive:signer-0123456789abcdef",
           "serverVersion": "1.4.0", "serverVersionPinned": True}


def record(verified=True):
    src = {"origin": "mcp-server", "thirdParty": True, **(BINDING if verified else {"serverChecksumVerified": False})}
    findings = [{"id": "finding-001", "category": "missing-control", "status": "open", "affectedComponents": ["cc-001"]}]
    if not verified:
        findings.append({"id": "finding-002", "category": "tool-definition-binding", "status": "open",
                         "affectedComponents": ["cc-001"]})
    return {
        "version": 1,
        "metadata": {"session": {"id": "sess-042/1/0"}},
        "contextComponents": [{"id": "cc-001", "type": "tool-definition", "label": "mcp-tool:fetch/fetch",
                               "source": src, "sanitization": {},
                               "findingRefs": [f["id"] for f in findings]}],
        "findings": findings,
        "sessionSummary": {"sessionAuditClean": False, "auditCleanBlockers": [f["id"] for f in findings],
                           "auditTrailComplete": verified},
        "schema": {"fieldGlossary": {k: "x" for k in consistency.GLOSSARY_KEYS}},
    }


def test_consistent_records_pass():
    assert consistency.check(record(True)) == []
    assert consistency.check(record(False)) == []


def test_verified_binding_cannot_both_report_and_decline_server_version():
    """A component cannot claim a serverVersion the server reported and also
    list source.serverVersion as not collected. That is a direct contradiction
    about the same fact, not honesty about an absent one."""
    doc = record(True)
    doc["contextComponents"][0]["notCollected"] = ["source.serverVersion"]
    errs = consistency.check(doc)
    assert any("notCollected" in e for e in errs)


def test_verified_binding_may_decline_server_version_via_not_collected():
    """Ledger ruling (Task 8, applied Task 9): a live server that never reports
    its own version omits source.serverVersion and lists it in notCollected,
    rather than inventing a value. That form must satisfy the same check a
    present, non-empty serverVersion does."""
    doc = record(True)
    doc["contextComponents"][0]["source"].pop("serverVersion")
    doc["contextComponents"][0]["notCollected"] = ["source.serverVersion"]
    assert consistency.check(doc) == []


MUTATIONS = {
    "clean-with-open": (True, lambda d: d["sessionSummary"].update(sessionAuditClean=True), "sessionAuditClean"),
    "blocker-dropped": (True, lambda d: d["sessionSummary"].update(auditCleanBlockers=[]), "auditCleanBlockers"),
    "trail-complete-unverified": (False, lambda d: d["sessionSummary"].update(auditTrailComplete=True),
                                  "auditTrailComplete"),
    "verified-without-session": (True, lambda d: d["contextComponents"][0]["source"].pop("sessionId"),
                                 "binding fields"),
    "verified-bad-approver": (True, lambda d: d["contextComponents"][0]["source"].update(authorizedBy="alice"),
                              "binding fields"),
    "full-without-label": (True, lambda d: d["contextComponents"][0].update(
        toolDefinitionTrustInversion={"detected": False, "mitigationStatus": "full"}), "trust label"),
    "inversion-without-finding": (True, lambda d: d["contextComponents"][0].update(
        toolDefinitionTrustInversion={"detected": True}), "trust-inversion finding"),
    "bad-label": (True, lambda d: d["contextComponents"][0].update(label="fetch"), "label"),
    "no-integrity-finding": (False, lambda d: (d["findings"].pop(),
                                               d["contextComponents"][0].update(findingRefs=["finding-001"]),
                                               d["sessionSummary"].update(auditCleanBlockers=["finding-001"])),
                             "exactly one open integrity finding"),
    "version-2": (True, lambda d: d.update(version=2), "version"),
    "glossary-gap": (True, lambda d: d["schema"]["fieldGlossary"].pop("source.authorizedBy"), "fieldGlossary"),
    "glossary-gap-model-output": (True, lambda d: d["schema"]["fieldGlossary"].pop("byType.modelOutput"),
                                  "fieldGlossary"),
    "glossary-gap-trust-label": (True, lambda d: d["schema"]["fieldGlossary"].pop("sanitization.trustLabel"),
                                 "fieldGlossary"),
    "glossary-gap-server-version": (True, lambda d: d["schema"]["fieldGlossary"].pop("source.serverVersion"),
                                    "fieldGlossary"),
    "session-id": (True, lambda d: d["metadata"]["session"].update(id="sess-042"), "metadata.session.id"),
    "stale-refs": (True, lambda d: d["contextComponents"][0].update(findingRefs=[]), "findingRefs"),
    "verified-missing-server-version": (True, lambda d: d["contextComponents"][0]["source"].pop("serverVersion"),
                                        "binding fields"),
    "verified-bad-version-pinned": (True, lambda d: d["contextComponents"][0]["source"].update(
        serverVersionPinned="yes"), "binding fields"),
    # Spec 9.4 row 3: a blocked tool gets no component, only a session-scoped
    # finding. Each mutation below turns finding-001 into a tool-definition-blocked
    # finding that violates exactly one of the three blocked-tool rules, keeping the
    # other two satisfied so the needle isolates the rule under test.
    "blocked-affected-components": (True, lambda d: (
        d["findings"][0].update(category="tool-definition-blocked", status="mitigated",
                                evidence={"componentId": "session", "serverId": "other-server",
                                          "name": "other-tool"}),
        d["sessionSummary"].update(sessionAuditClean=True, auditCleanBlockers=[]),
    ), "affectedComponents"),
    "blocked-bad-component-id": (True, lambda d: (
        d["findings"][0].update(category="tool-definition-blocked", status="mitigated", affectedComponents=[],
                                evidence={"componentId": "cc-001", "serverId": "other-server",
                                          "name": "other-tool"}),
        d["contextComponents"][0].update(findingRefs=[]),
        d["sessionSummary"].update(sessionAuditClean=True, auditCleanBlockers=[]),
    ), "componentId"),
    "blocked-label-collision": (True, lambda d: (
        d["findings"][0].update(category="tool-definition-blocked", status="mitigated", affectedComponents=[],
                                evidence={"componentId": "session", "serverId": "fetch", "name": "fetch"}),
        d["contextComponents"][0].update(findingRefs=[]),
        d["sessionSummary"].update(sessionAuditClean=True, auditCleanBlockers=[]),
    ), "assembled component"),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_rule_catches_its_violation(name):
    verified, mutate, needle = MUTATIONS[name]
    doc = copy.deepcopy(record(verified))
    mutate(doc)
    assert any(needle in e for e in consistency.check(doc)), consistency.check(doc)


def test_blocked_tool_never_assembled_passes():
    """Spec 9.4 row 3: blocked this session, never assembled. No component,
    just a session-scoped finding."""
    doc = {
        "version": 1,
        "metadata": {"session": {"id": "sess-042/1/0"}},
        "contextComponents": [],
        "findings": [{"id": "finding-009", "category": "tool-definition-blocked", "status": "mitigated",
                      "affectedComponents": [],
                      "evidence": {"componentId": "session", "serverId": "fetch", "name": "fetch"}}],
        "sessionSummary": {"sessionAuditClean": True, "auditCleanBlockers": [], "auditTrailComplete": True},
        "schema": {"fieldGlossary": {k: "x" for k in consistency.GLOSSARY_KEYS}},
    }
    assert consistency.check(doc) == []


def test_blocked_tool_incorrectly_assembled_is_rejected():
    """Regression: a fully verified tool-definition component whose only finding
    is tool-definition-blocked, naming that component, must be rejected. A blocked
    tool never reaches assembly (spec 9.4 row 3), so it can never also be a
    fully verified component in the same record."""
    doc = record(True)
    doc["findings"] = [{"id": "finding-009", "category": "tool-definition-blocked", "status": "mitigated",
                        "affectedComponents": ["cc-001"],
                        "evidence": {"componentId": "cc-001", "serverId": "fetch", "name": "fetch"}}]
    doc["contextComponents"][0]["findingRefs"] = ["finding-009"]
    doc["sessionSummary"].update(sessionAuditClean=True, auditCleanBlockers=[])
    errs = consistency.check(doc)
    assert any("affectedComponents" in e for e in errs)
    assert any("componentId" in e for e in errs)
    assert any("assembled component" in e for e in errs)


def test_anonymity_finds_home_paths():
    doc = record()
    assert consistency.anonymity(doc, "/home/demo") == []
    doc["contextComponents"][0]["source"]["origin"] = "file:///Users/someone/notes.txt"
    assert consistency.anonymity(doc, "/home/demo") == ["record carries a home path"]
    doc["contextComponents"][0]["source"]["origin"] = "/srv/acct/x"
    assert consistency.anonymity(doc, "/srv/acct") == ["record carries a home path"]
    assert consistency.anonymity(record(), "/") == []


LEAK_MESSAGE = ["record carries a local path, a file: URI, an IP literal, or an email address"]


def test_anonymity_finds_local_paths_file_uris_and_ip_hosts():
    """Spec 3 forbids absolute paths and IP addresses. These are not under
    a home directory, so only the location check (not the home-path check)
    can catch them."""
    doc = record()
    doc["contextComponents"][0]["source"]["origin"] = "/opt/other/data.txt"
    assert consistency.anonymity(doc, "/") == LEAK_MESSAGE
    doc = record()
    doc["contextComponents"][0]["source"]["origin"] = "file:///srv/corpus/a.txt"
    assert consistency.anonymity(doc, "/") == LEAK_MESSAGE
    doc = record()
    doc["contextComponents"][0]["source"]["uri"] = "http://10.0.0.5/doc"
    assert consistency.anonymity(doc, "/") == LEAK_MESSAGE
    doc = record()
    doc["contextComponents"][0]["source"]["uri"] = "http://[2001:db8::1]/doc"
    assert consistency.anonymity(doc, "/") == LEAK_MESSAGE


def test_anonymity_accepts_legitimate_locations():
    doc = record()
    doc["contextComponents"][0]["source"]["origin"] = "https://example.com/doc"
    doc["contextComponents"][0]["source"]["uri"] = "cxbom-attest:s1#3"
    doc["contextComponents"][0]["label"] = "mcp-tool:fetch/fetch"
    assert consistency.anonymity(doc, "/") == []


@pytest.mark.parametrize("value", [
    "10.0.0.5", "see http://10.0.0.5:80/x", "alice@evil.corp", "reach me at bob.smith+cx@mail.example.org",
    "fe80::1%eth0", "peer [2001:db8::1]:443 answered", "mapped ::ffff:10.0.0.5",
])
def test_leaks_location_finds_ip_literals_and_emails_anywhere(value):
    """Final review I2: an IP literal or an email address is caught anywhere
    in a string, not only as the whole string or a URL's host."""
    assert consistency.leaks_location(value) is True
    doc = record()
    doc["contextComponents"][0]["label"] = value
    assert consistency.anonymity(doc, "/") == LEAK_MESSAGE


@pytest.mark.parametrize("value", [
    "llama.cpp", "vLLM 0.11", "2025.4.7", "cxbom-attest:3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11#3",
    "2026-10-10T18:06:00Z", "std::vector", "npx @scope/server@1.2.3", "urn:uuid:3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11",
    "unverified-approver:demo-operator:interactive:signer-0123456789abcdef", "999.1.1.1",
])
def test_leaks_location_accepts_ordinary_strings(value):
    assert consistency.leaks_location(value) is False
