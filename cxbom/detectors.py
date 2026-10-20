"""Structural tool-definition trust-inversion detector.

Deterministic and structural-only: it detects the assembly-time STRUCTURE of a
trust inversion (a third-party tool definition assembled with ring-0-equivalent
positional authority and no trust-downgrade boundary) from observable facts, not
from a label the pipeline pre-set. It does not detect behavioral exploitation.

Owner: ATACE Working Group.
"""
from __future__ import annotations


def detect_trust_inversion(component: dict) -> dict:
    src = component.get("source", {})
    is_tool_def = component.get("type") == "tool-definition"
    third_party = src.get("thirdParty") is True
    position = component.get("content", {}).get("positionInContext", "")
    in_schema_block = "tool-schema" in position
    # A trust-downgrade wrapper (an injected trust label) neutralizes the inversion.
    has_downgrade = bool(component.get("sanitization", {}).get("trustLabel"))

    if is_tool_def and third_party and in_schema_block and not has_downgrade:
        return {
            "detected": True,
            "severity": "high",
            "description": (
                "External tool definition assembled in a tool-schema block with "
                "ring-0-equivalent positional authority and no trust-downgrade "
                "boundary (structural detection)."
            ),
            "positionalAuthority": "ring-0-equivalent",
            "claimedAuthority": "ring-1",
            "authorityMismatch": True,
            "mitigationStatus": "none",
            "mitigationRequired": ["trust-tier-downgrade-label", "server-integrity-verification"],
        }
    return {
        "detected": False,
        "reason": (
            "Not a third-party tool definition with ring-0-equivalent positional "
            "authority, or a trust-downgrade boundary is present."
        ),
    }
