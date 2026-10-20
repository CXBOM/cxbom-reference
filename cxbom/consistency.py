"""Tool-side record meaning checks the 0.2.0 schema cannot state (spec 3, 9.4, 11).

Owner: ATACE Working Group.

The vendored validator checks structure, honesty and numbers. These checks
add what the cxbom tool itself promises about a record: the audit summary
agrees with the findings, a verified integrity claim carries its binding
fields, integrity never raises mitigationStatus, a blocked tool never also
shows up as an assembled component, and every unverified tool carries
exactly one open integrity finding. `cxbom validate` runs both.
anonymity() is separate because it needs the account home path.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

GLOSSARY_KEYS = ("source.serverChecksumVerified", "source.authorizedBy", "content.tokenCount",
                 "content.contextualSharePercent", "metadata.session.id", "sessionSummary.sessionAuditClean",
                 "byType.modelOutput", "sanitization.trustLabel", "source.serverVersion")
_SESSION_ID = re.compile(r"^.+/\d+/\d+$")
_TOOL_LABEL = re.compile(r"^mcp-(tool:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}/.+|instructions:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})$")
_HOME = re.compile(r"(^|[^A-Za-z0-9])/(Users|home)/[^/\s]+")
_INTEGRITY = {"tool-definition-change", "tool-definition-binding"}
# Candidate IP literals inside free text. The lookarounds keep a candidate from
# starting or ending inside a longer word or number, so "cxbom-attest:<uuid>#3",
# "T18:06:00Z" and "2025.4.7" never form one. ipaddress then decides, so a
# candidate that only looks numeric (four octets over 255, a bare time) passes.
_IPV4_CANDIDATE = re.compile(r"(?<![0-9.])\d{1,3}(?:\.\d{1,3}){3}(?![0-9])(?!\.\d)")
_IPV6_CANDIDATE = re.compile(r"(?<![0-9A-Za-z:.])[0-9A-Fa-f.]*:[0-9A-Fa-f.:]*:[0-9A-Fa-f.:]*(?![0-9A-Za-z:])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


def check(doc: dict) -> list[str]:
    errs: list[str] = []
    comps = doc.get("contextComponents", [])
    found = doc.get("findings", [])
    ss = doc.get("sessionSummary", {})
    open_ids = sorted(f["id"] for f in found if f.get("status") == "open")
    if ss.get("sessionAuditClean") is not (not open_ids):
        errs.append("sessionAuditClean must be true exactly when no finding is open")
    blockers = ss.get("auditCleanBlockers", [])
    if sorted(blockers) != open_ids or len(set(blockers)) != len(blockers):
        errs.append("auditCleanBlockers must equal the set of open finding ids")
    tools = [c for c in comps if c.get("type") == "tool-definition"]
    unverified = [c["id"] for c in tools if c.get("source", {}).get("serverChecksumVerified") is not True]
    if ss.get("auditTrailComplete") is not (not unverified):
        errs.append("auditTrailComplete must be false exactly when a tool definition is unverified")
    if doc.get("version") != 1:
        errs.append("version must be 1")
    gloss = doc.get("schema", {}).get("fieldGlossary", {})
    errs += [f"fieldGlossary is missing {k}" for k in GLOSSARY_KEYS if k not in gloss]
    if not _SESSION_ID.fullmatch(str(doc.get("metadata", {}).get("session", {}).get("id", ""))):
        errs.append("metadata.session.id must be <session_id>/<turn>/<inference_index>")
    ids = {c.get("id") for c in comps}
    for f in found:
        for cid in f.get("affectedComponents", []):
            if cid not in ids:
                errs.append(f"{f['id']}: affectedComponents names unknown component {cid}")
    # Spec 9.4 row 3: a tool blocked before assembly never becomes a component.
    # Its finding stands alone, scoped to the session, not to a component the
    # model never saw.
    for f in found:
        if f.get("category") != "tool-definition-blocked":
            continue
        ev = f.get("evidence", {})
        if f.get("affectedComponents", []) != []:
            errs.append(f"{f['id']}: a blocked tool finding must carry affectedComponents []")
        if ev.get("componentId") != "session":
            errs.append(f"{f['id']}: a blocked tool finding must carry evidence.componentId 'session'")
        blocked_label = f"mcp-tool:{ev.get('serverId')}/{ev.get('name')}"
        if any(c.get("type") == "tool-definition" and c.get("label") == blocked_label for c in comps):
            errs.append(f"{f['id']}: a blocked tool must never also appear as an assembled component")
    for c in comps:
        cid, src = c.get("id"), c.get("source", {})
        refs = sorted(f["id"] for f in found if cid in f.get("affectedComponents", []))
        if sorted(c.get("findingRefs", [])) != refs:
            errs.append(f"{cid}: findingRefs must list exactly the findings that name it")
        if src.get("serverChecksumVerified") is True:
            psid = src.get("sessionId")
            # Spec 9.4 "allowed and bound" row: serverVersion and serverVersionPinned
            # are recorded alongside the checksum, not left to default absence.
            # Ledger ruling (Task 8, applied Task 9): a live server that never
            # reports its own version (Binding.server_version is None) omits
            # source.serverVersion rather than inventing one, and lists
            # "source.serverVersion" in the component's notCollected instead.
            # Either a non-empty serverVersion or that exact notCollected form
            # satisfies this check. Inventing a value would be dishonest, and
            # silently accepting bare absence would hide a fact the emitter
            # could have declared "not asserted".
            has_version = isinstance(src.get("serverVersion"), str) and bool(src.get("serverVersion"))
            not_collected = c.get("notCollected", [])
            declined_version = "serverVersion" not in src and "source.serverVersion" in not_collected
            # A server that did report a version and a component that says the
            # version was never collected cannot both be true. Accepting this
            # would let a caller assert honesty on both sides of a fact.
            if has_version and "source.serverVersion" in not_collected:
                errs.append(f"{cid}: source.serverVersion is present and cannot also be in notCollected")
            if c.get("type") != "tool-definition" or not psid or \
                    not str(src.get("uri", "")).startswith(f"cxbom-attest:{psid}#") or \
                    "serverChecksum" not in src or "retrievedAt" not in src or \
                    not str(src.get("authorizedBy", "")).startswith("unverified-approver:") or \
                    not (has_version or declined_version) or \
                    not isinstance(src.get("serverVersionPinned"), bool):
                errs.append(f"{cid}: serverChecksumVerified needs a bound tool definition with its binding fields")
        tdi = c.get("toolDefinitionTrustInversion") or {}
        if tdi.get("mitigationStatus") == "full" and not c.get("sanitization", {}).get("trustLabel"):
            errs.append(f"{cid}: mitigationStatus full needs a registered trust label")
        if tdi.get("detected") and not any(f.get("category") == "trust-inversion" and
                                           cid in f.get("affectedComponents", []) for f in found):
            errs.append(f"{cid}: detected inversion has no trust-inversion finding")
        if c.get("type") == "tool-definition":
            if not _TOOL_LABEL.fullmatch(str(c.get("label", ""))):
                errs.append(f"{cid}: tool components carry label mcp-tool:<serverId>/<name>")
            integrity = [f for f in found if f.get("category") in _INTEGRITY and f.get("status") == "open"
                         and cid in f.get("affectedComponents", [])]
            if cid in unverified and len(integrity) != 1:
                errs.append(f"{cid}: an unverified tool needs exactly one open integrity finding")
            if cid not in unverified and integrity:
                errs.append(f"{cid}: a verified tool must not carry an integrity finding")
    return errs


def _strings(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)
    elif isinstance(node, str):
        yield node


def _ip_literal_host(value: str) -> bool:
    """True when value parses as a URL whose host is an IPv4 or IPv6 literal."""
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return False
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _contains_ip_literal(value: str) -> bool:
    """True when an IPv4 or IPv6 literal appears anywhere in value, not only as a URL host."""
    for m in _IPV4_CANDIDATE.finditer(value):
        try:
            ipaddress.IPv4Address(m.group(0))
            return True
        except ValueError:
            continue
    for m in _IPV6_CANDIDATE.finditer(value):
        # A sentence can end right after an address, so a trailing dot is not part of it.
        candidate = m.group(0).rstrip(".")
        try:
            ipaddress.IPv6Address(candidate)
            return True
        except ValueError:
            continue
    return False


def leaks_location(value: str) -> bool:
    """True when a string is a local path or file: URI, or carries an IP literal or an email address.

    Spec 3 forbids absolute paths and IP addresses in a record. Both name
    infrastructure the record's anonymity promise exists to hide, and an
    email address names a person the same way. An IP literal or an email
    address is caught anywhere in the string (final review I2), since a
    server-chosen string can embed one in prose or in a URL path, not only
    in a URL's host.
    Assembly.retrieved_document calls this to refuse origin and uri at
    construction time, and anonymity() calls it on every string already in a
    built record, since a leak could reach the record through a field
    retrieved_document does not gate.
    """
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("/"):
        return True
    if value.lower().startswith("file:"):
        return True
    return _ip_literal_host(value) or _contains_ip_literal(value) or bool(_EMAIL.search(value))


def looks_like_home_path(value: str) -> bool:
    """True when a string carries a /Users/<name> or /home/<name> segment.

    Unlike anonymity()'s own home-path check, this does not need the current
    account's actual home directory: it catches the general shape, which is
    what a server-chosen string (a blocked tool's name, a reported version)
    must be screened against before it enters a finding or a component,
    independent of which machine happens to be running the emitter.
    """
    return bool(_HOME.search(value))


def anonymity(doc: dict, home: str) -> list[str]:
    for s in _strings(doc):
        if (len(home) > 1 and home in s) or looks_like_home_path(s):
            return ["record carries a home path"]
        if leaks_location(s):
            return ["record carries a local path, a file: URI, an IP literal, or an email address"]
    return []
