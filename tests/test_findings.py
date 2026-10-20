"""Every finding template passes the vendored validator and resolves in the catalogs (spec 10).

Owner: ATACE Working Group.
"""
import copy
import json
from pathlib import Path

import pytest

from cxbom import conformance, crosswalk, findings

MINIMAL = json.loads((Path(__file__).resolve().parent / "fixtures/atace/valid-minimal.json").read_text(encoding="utf-8"))
AT = "2026-10-10T18:05:00Z"
DETECTION = {"detected": True, "severity": "high", "description": "structural", "mitigationStatus": "none"}

TEMPLATES = {
    "trust-inversion": findings.trust_inversion("finding-001", "cc-002", "cxbom-attest:x#2", DETECTION, AT),
    "change": findings.definition_changed("finding-001", "cc-002", "cxbom-attest:x#2", AT),
    "blocked": findings.definition_blocked("finding-001", "fetch", "fetch", "changed", "cxbom-attest:x#2", AT),
    "binding": findings.binding_failed("finding-001", "cc-002", "", "no proxy session", AT),
    "role-marker": findings.special_token("finding-001", "cc-002", "tool-execution", True, ["<|system|>"], AT),
    "special": findings.special_token("finding-001", "cc-002", "tool-execution", False, ["<s>"], AT),
    "special-spelled": findings.special_token("finding-001", "cc-002", "reasoning", False, ["<think>"], AT,
                                              spelled=["<think>"]),
    "special-mixed": findings.special_token("finding-001", "cc-002", "reasoning", False,
                                            ["<think>", "<tool_call>"], AT, spelled=["<think>"]),
    "missing-injection": findings.missing_control("finding-001", "injection", ["cc-001"], ["system-prompt"], AT),
    "missing-pii": findings.missing_control("finding-001", "pii", ["cc-001"], ["system-prompt"], AT),
    "missing-credentials": findings.missing_control("finding-001", "credentials", ["cc-001"], ["system-prompt"], AT),
}

EXPECTED = {  # spec 10: title, severity, category, cweRef, owaspRefs, status
    "trust-inversion": ("Tool Definition Trust Inversion", "high", "trust-inversion", "CWE-345", ["LLM01", "LLM04"], "open"),
    "change": ("MCP tool definition changed since approval", "high", "tool-definition-change", "CWE-345", ["LLM04"], "open"),
    "blocked": ("MCP tool definition blocked before assembly", "low", "tool-definition-blocked", "CWE-345", ["LLM04"], "mitigated"),
    "binding": ("Tool integrity could not be bound to a live proxy session", "medium", "tool-definition-binding",
                "CWE-345", ["LLM04"], "open"),
    "role-marker": ("Chat role marker inside non-scaffold content", "high", "special-token-injection", "CWE-1427",
                    ["LLM01"], "open"),
    "special": ("Special token inside non-scaffold content", "medium", "special-token-injection", "CWE-1427",
                ["LLM01"], "open"),
    "special-spelled": ("Special token inside non-scaffold content", "medium", "special-token-injection",
                        "CWE-1427", ["LLM01"], "open"),
    "special-mixed": ("Special token inside non-scaffold content", "medium", "special-token-injection",
                      "CWE-1427", ["LLM01"], "open"),
    "missing-injection": ("Security fields not collected: injection and scanner fields", "low", "missing-control",
                          "CWE-1427", ["LLM01"], "open"),
    "missing-pii": ("Security fields not collected: PII", "low", "missing-control", "", ["LLM02"], "open"),
    "missing-credentials": ("Security fields not collected: credentials and secrets", "low", "missing-control", "",
                            ["LLM02"], "open"),
}


@pytest.mark.parametrize("key", sorted(TEMPLATES))
def test_template_fields_match_spec(key):
    f = TEMPLATES[key]
    assert (f["title"], f["severity"], f["category"], f["cweRef"], f["owaspRefs"], f["status"]) == EXPECTED[key]
    assert f["formalRef"] == ""


@pytest.mark.parametrize("key", sorted(TEMPLATES))
def test_template_passes_validator_and_resolves(key):
    doc = copy.deepcopy(MINIMAL)
    doc["findings"] = [TEMPLATES[key]]
    assert conformance.check_all(doc) == []
    cwe = crosswalk.load_catalog("cwe")
    llm = crosswalk.load_catalog("owasp-llm-2026")
    f = TEMPLATES[key]
    assert f["cweRef"] == "" or f["cweRef"] in cwe
    assert all(code in llm for code in f["owaspRefs"])


def test_blocked_finding_points_at_the_session():
    f = TEMPLATES["blocked"]
    assert f["affectedComponents"] == [] and f["evidence"]["componentId"] == "session"


WORDING = json.loads((Path(__file__).resolve().parent / "fixtures" / "findings-wording.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("key", sorted(TEMPLATES))
def test_description_and_remediation_wording_is_locked(key):
    # A wording change to a finding changes what the record claims, so it must be a deliberate fixture edit.
    f = TEMPLATES[key]
    assert {"description": f["description"], "remediation": f["remediation"]} == WORDING[key]


def test_missing_control_needs_a_component():
    with pytest.raises(ValueError):
        findings.missing_control("finding-001", "pii", [], [], "2026-10-10T18:05:00Z")


def test_spelled_tokens_follow_found_and_ignore_names_outside_it():
    # The description lists spelled tokens in the evidence order, and a name the
    # evidence does not hold cannot make the sentence claim it.
    f = findings.special_token("finding-001", "cc-002", "reasoning", False, ["<a>", "<b>", "<c>"], AT,
                               spelled=["<c>", "<zz>", "<a>"])
    assert f["description"] == ("Component text contains tokenizer control tokens. The model reads <b> as "
                                "structure. The text only spells <a>, <c>, which the component's ids do not carry. "
                                "Re-tokenizing the text would turn those into structure.")
    only_outside = findings.special_token("finding-001", "cc-002", "reasoning", False, ["<s>"], AT, spelled=["<zz>"])
    assert only_outside["description"] == TEMPLATES["special"]["description"]
