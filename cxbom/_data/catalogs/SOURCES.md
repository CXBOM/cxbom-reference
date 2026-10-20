# Vendored catalog snapshots

Each `*.json` is an `{id: canonical_title}` snapshot of a public security taxonomy,
recorded as factual reference data with source attribution. Content hashes and
machine-readable provenance are in `SOURCES.json`; the crosswalk validator
recomputes each hash and fails on mismatch.

| File | Released | Pin | Source |
|---|---|---|---|
| `owasp-llm-2025.json` | yes (2025) | official 2025 list | https://genai.owasp.org/llm-top-10/ |
| `owasp-llm-2026.json` | **yes (2026)** | official release, commit `d027bb64`, ref `2026-final`, path `2026/final` | https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final |
| `owasp-asi-2026.json` | yes (Version 2026, Dec 2025) | official release | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ |
| `cwe.json` | yes | verified 2026-07-11 | https://cwe.mitre.org/ |
| `atlas.json` | yes | verified 2026-07-11 | https://github.com/mitre-atlas/atlas-data |

## Gate

The crosswalk validator's submission-mode gate (`--submission`) fails any catalog
pin that is not an official release: a `null` `releaseTag`, a tag matching
`rc`/`candidate`/`draft`/`sprint`/`preview`/`-pre`, or `released: false`. Both the
OWASP LLM 2026 and ASI 2026 lists are official releases (rankings and content
final and locked), so submission mode stays clean.

## Verified renumbering (2025 to 2026, by name)

Supply Chain LLM03 to LLM04 - Data and Model Poisoning LLM04 to LLM05 -
Improper Output Handling LLM05 to LLM10 - Excessive Agency LLM06 to LLM03 -
Misinformation LLM09 to LLM07 - Vector and Embedding Weaknesses LLM08 to LLM09 -
Unbounded Consumption LLM10 to LLM06 - Prompt Injection LLM01 and Sensitive
Information Disclosure LLM02 unchanged. 2025 "System Prompt Leakage" (LLM07) has
no same-name successor; it was reworked into 2026 LLM08 "Hidden Context Exposure"
(a documented rename exception).

ASI01 released title is "Agent Goal Hijack"; the Sprint-1 first-public-draft
(commit `e1deaca6`) used the earlier "Agent Behaviour Hijack".

Attribution: OWASP GenAI content is CC-BY-SA-4.0. Only factual id-to-title
reference data is recorded here, with the source cited above.
