"""Exact finding templates (spec 10).

Owner: ATACE Working Group.

Every finding the emitter writes comes from one of these functions, so the
title, severity, category, CWE and OWASP references stay fixed. formalRef is
empty for every template: it names no numbered result from an earlier draft.
"""
from __future__ import annotations

TOOL_LAYER = "tool-execution"

MISSING_CONTROL_GROUPS = {
    "injection": ("injection and scanner fields", ["LLM01"], "CWE-1427",
                  ("injectionRiskRating", "sanitization.scanner", "sanitization.scannerVersion",
                   "sanitization.scannedAt")),
    "pii": ("PII", ["LLM02"], "", ("containsPII",)),
    "credentials": ("credentials and secrets", ["LLM02"], "", ("containsCredentials", "containsSecretsOrKeys")),
}


def _finding(fid: str, *, title: str, severity: str, category: str, cwe: str, owasp: list[str],
             components: list[str], layers: list[str], description: str, evidence: dict,
             remediation: tuple[list[str], list[str], list[str]], status: str, at: str,
             formal_ref: str = "", agentic: list[str] | None = None) -> dict:
    out = {
        "id": fid, "title": title, "severity": severity, "category": category, "cweRef": cwe,
        "owaspRefs": owasp, "formalRef": formal_ref, "affectedComponents": components,
        "affectedLayers": layers, "description": description, "evidence": evidence,
        "remediation": {"immediate": remediation[0], "shortTerm": remediation[1], "strategic": remediation[2]},
        "status": status, "detectedAt": at,
    }
    if agentic is not None:
        out["agenticRefs"] = agentic
    return out


def trust_inversion(fid: str, component_id: str, source_uri: str, detection: dict, at: str) -> dict:
    return _finding(
        fid, title="Tool Definition Trust Inversion", severity=detection["severity"], category="trust-inversion",
        cwe="CWE-345", owasp=["LLM01", "LLM04"], agentic=["ASI02", "ASI04"], formal_ref="",
        components=[component_id], layers=[TOOL_LAYER], description=detection["description"],
        evidence={"componentId": component_id, "sourceUri": source_uri},
        remediation=(["Apply a registered trust-downgrade label to the external tool definition"],
                     ["Keep the server pinned and bound to a live proxy session"],
                     ["Assemble external tool definitions outside the operator's tool-schema block"]),
        status="open", at=at)


def definition_changed(fid: str, component_id: str, source_uri: str, at: str) -> dict:
    return _finding(
        fid, title="MCP tool definition changed since approval", severity="high",
        category="tool-definition-change", cwe="CWE-345", owasp=["LLM04"], components=[component_id],
        layers=[TOOL_LAYER],
        description="The proxy saw a definition whose hash differs from the signed pin, and it was assembled.",
        evidence={"componentId": component_id, "sourceUri": source_uri},
        remediation=(["Stop the session and review the changed definition"],
                     ["Run the proxy in enforce mode so changed definitions are blocked"],
                     ["Re-approve only after reviewing the new definition text"]),
        status="open", at=at)


def definition_blocked(fid: str, server_id: str, name: str, verdict: str, source_uri: str, at: str) -> dict:
    return _finding(
        fid, title="MCP tool definition blocked before assembly", severity="low",
        category="tool-definition-blocked", cwe="CWE-345", owasp=["LLM04"], components=[],
        layers=[TOOL_LAYER],
        description=f"The proxy blocked tool {server_id}/{name} (verdict {verdict}) and it never reached the context.",
        evidence={"componentId": "session", "sourceUri": source_uri, "serverId": server_id, "name": name,
                  "verdict": verdict},
        remediation=(["None required. The proxy removed the definition before the model saw it"],
                     ["Review the change with cxbom approve if it is expected"],
                     ["Keep the server in enforce mode"]),
        status="mitigated", at=at)


def binding_failed(fid: str, component_id: str, source_uri: str, reason: str, at: str) -> dict:
    return _finding(
        fid, title="Tool integrity could not be bound to a live proxy session", severity="medium",
        category="tool-definition-binding", cwe="CWE-345", owasp=["LLM04"], components=[component_id],
        layers=[TOOL_LAYER],
        description="The component is recorded unverified because no live proxy session proves its signed pin.",
        evidence={"componentId": component_id, "sourceUri": source_uri, "reason": reason},
        remediation=(["Route the server through cxbom proxy with a signed lock"],
                     ["Pass the proxySessionId from the listing into the assembly"],
                     ["Fail the pipeline gate on unverified tool definitions"]),
        status="open", at=at)


def special_token(fid: str, component_id: str, layer: str, role_marker: bool, found: list[str], at: str, *,
                  spelled: list[str] | None = None) -> dict:
    """spelled names the tokens in found that the text spells and the ids do not carry.

    Generated ids can spell a control token in plain pieces. The model read the
    plain ids, so the default sentence would overstate the prompt for those
    tokens. The description says, token by token, which the model reads as
    structure and which only the text spells. The severity stays: re-tokenizing
    the text gives the token.
    """
    spelled = [t for t in found if t in (spelled or [])]
    carried = [t for t in found if t not in spelled]
    if not spelled:
        description = "Component text contains tokenizer control tokens that the model reads as structure."
    elif not carried:
        description = ("Component text spells tokenizer control tokens that the component's ids do not carry. "
                       "Re-tokenizing the text would turn them into structure.")
    else:
        description = (f"Component text contains tokenizer control tokens. The model reads {', '.join(carried)} "
                       f"as structure. The text only spells {', '.join(spelled)}, which the component's ids do not "
                       "carry. Re-tokenizing the text would turn those into structure.")
    title = "Chat role marker inside non-scaffold content" if role_marker else \
        "Special token inside non-scaffold content"
    return _finding(
        fid, title=title, severity="high" if role_marker else "medium", category="special-token-injection",
        cwe="CWE-1427", owasp=["LLM01"], components=[component_id], layers=[layer],
        description=description,
        evidence={"componentId": component_id, "sourceUri": "", "tokens": found},
        remediation=(["Remove or escape the control tokens before assembly"],
                     ["Reject content carrying chat markers at ingestion"],
                     ["Tokenize untrusted content with special-token splitting disabled"]),
        status="open", at=at)


def missing_control(fid: str, group: str, component_ids: list[str], layers: list[str], at: str) -> dict:
    if not component_ids:
        raise ValueError("missing_control needs at least one component id")
    label, owasp, cwe, fields = MISSING_CONTROL_GROUPS[group]
    return _finding(
        fid, title=f"Security fields not collected: {label}", severity="low", category="missing-control",
        cwe=cwe, owasp=list(owasp), components=component_ids, layers=layers,
        description=f"No scanner supplied {', '.join(fields)}. The record marks them notCollected.",
        evidence={"componentId": component_ids[0], "sourceUri": ""},
        remediation=(["Attach a scanner callback to the assembly"],
                     ["Record scanner name, version and time for every component"],
                     ["Gate on missing-control findings with --fail-on any-strict"]),
        status="open", at=at)
