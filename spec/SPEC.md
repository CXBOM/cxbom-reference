# CxBOM specification 0.3.0

Context Bill of Materials. Version 0.3.0. Maintained by the ATACE Working Group.

The JSON Schema at `https://cxbom.org/schema/0.3.0/cxbom.schema.json` is the
normative definition of a CxBOM 0.3.0 record. This document explains what the
schema records and why. Where the two differ, the schema wins.

## Purpose

When a security team investigates an incident in an LLM agent, it needs to
answer one question first: what did the model see? That means each piece of
content, where it came from, what trust tier it held, what sanitization it
passed through, and which controls were absent.

A Context Bill of Materials (CxBOM) answers that question. It is a structured,
machine-processable record of every component that enters the context-assembly
pipeline at inference time, with provenance, integrity, and trust metadata
attached to each one. CxBOM is to the context-assembly pipeline what a Software
Bill of Materials is to a software supply chain.

CxBOM is a design contribution. It has not been evaluated in production, and
its value in incident response has not been measured against a baseline.

## Record boundary

A CxBOM record describes the composition of one model's context window at
assembly time, before inference. Orchestration state, such as queues,
schedulers, and messages in transit between agents, is outside the record until
it enters a context window. At that point it becomes a component with its own
provenance.

A multi-agent session emits one record per agent per turn. Session identifiers
link the records.

## Relationship to other bills of materials

CxBOM extends CycloneDX 1.6 instead of replacing it. A context record is a
sibling of the software and AI/ML bills of materials. Version 0.3.0 reuses the
CycloneDX component, dependency, and metadata structures, and adds an overlay
for context assembly.

Three kinds of record describe an AI system on different lifecycle axes:

- An AI/ML bill of materials records what the model is.
- An authority-envelope bill of materials, such as the AgentRiskBOM preprint
  proposal, records what the agent may do. It is generated per release.
- A CxBOM records what the model saw. It is generated per inference session.

These records cross-check by join keys (`metadata.agent.id`, `version`, and
`deploymentId`), not by reference. An authority envelope declares which
controls should have applied, and the CxBOM records whether they did.

## Record structure

A record is a JSON document with these required top-level fields:

| Field | Purpose |
|---|---|
| `bomFormat`, `specVersion`, `extends` | Identify the document as CxBOM 0.3.0 and name CycloneDX 1.6 as its parent |
| `serialNumber`, `version` | Identify this record instance |
| `metadata` | Generation event, the audited session, the model, and the agent |
| `trustModel` | The trust rings this deployment declares |
| `contextComponents` | Every component assembled into the context window |
| `controlLayers` | The defense-in-depth layers around the session, and their coverage |
| `findings` | Security findings raised against the session |
| `sessionSummary` | Token distribution, finding counts, and the audit gate |
| `schema` | The schema version and a field glossary |
| `catalogVersions` | Content-hashed pins for every taxonomy the record cites |
| `illustrative` | True for hand-authored records, false for emitted ones |

The [field reference](/reference/) lists every field, type, and allowed value.

## Trust model

The trust model has three rings:

| Ring | Tier | Holds |
|---|---|---|
| 0 | `operator` | Operator-authored content, such as the system prompt |
| 1 | `agent` | Agent-mediated content, such as tool definitions, tool results, and retrieved documents |
| 1 | `ring-1-derived` | Model-generated content that re-enters the context, such as an earlier assistant turn read back from memory |
| 2 | `user` | User input |

Ring assignment is a declared property of the assembly pipeline, not an
inference over content. The operator registers each ingestion path to a ring,
and each component inherits the ring of its path. A component that arrives on
an unregistered path must fail closed to the lowest trust tier and raise an
audit flag.

Rings describe assembly before inference only. A ring label confers no
computational privilege inside the model. Positional authority in a record means
where the pipeline placed a component, not how much weight the model gave it.

Version 0.3.0 removes the model-level attentionMechanism and
tokenDemocracyApplies fields and the session-level
dualFailureMultiplierAssessment object. The record carries observable
assembly facts (`architectureType`, `trustRing`, `positionInContext`, token
counts) and does not assert a model mechanism or a formal result.

## Context components

Each component records:

- a stable identifier, a type, and a subtype from the component taxonomy
- its trust ring, trust tier, and control layer
- the turn at which it was assembled (`assembledAtTurn`, where 0 means before the conversation)
- its source and provenance (`source`)
- a content attestation over the tokenized form: a SHA-256 digest, a token
  count, a share of the context, and a position (`content`)
- the sanitization controls applied and the controls expected but absent (`sanitization`)
- its permissions, audit flags, injection risk rating, and any findings that cite it

The component types are `system-prompt`, `tool-definition`, `tool-result`,
`retrieved-document`, and `user-turn`.

## Facts and judgments

A record carries two kinds of field and keeps them apart. Facts are what the
pipeline observed: source, hash, token count, and the controls applied.
Judgments are what the operator's policy asserts: trust ring, tier, and finding
severity. A judgment travels with the record for audit. It is not an observed
property of the content. CycloneDX mixes the two in the same way in its
vulnerability and attestation fields, and CxBOM follows that precedent.

## Token accounting

`sessionSummary.totalContextTokens` counts the tokens attributed to components.
`sessionSummary.templateOverheadTokens` counts the chat-template scaffolding and
special tokens that belong to no component. The two add up to the tokens the
model received:

```
contextWindowTokensUsed = totalContextTokens + templateOverheadTokens
```

The reference session on this site uses 46,205 tokens: 46,192 in six components
and 13 of template overhead. Its record is about 17 KB.

## Findings and the audit gate

A finding follows the structure of a vulnerability record. It has an identifier,
a title, a severity (`critical`, `high`, `medium`, or `low`), a category, a CWE
reference, OWASP references, the affected components and layers, a description,
evidence, a remediation, a status, and the time it was detected. An optional SLA
deadline routes it to an owner the way a CVE is routed.

The structural finding CxBOM defines is the Tool Definition Trust Inversion:
an externally authored ring 1 tool definition assembled with ring 0 positional
authority. The component records it under `toolDefinitionTrustInversion`, and
the finding cites the component.

`sessionSummary.sessionAuditClean` is true only when no finding is open.
`auditCleanBlockers` lists the findings that keep it false. A deployment
pipeline can use that field as a gate that fails a session while any finding
remains open.

## Using a record

A record that no one reads is shelfware, so CxBOM defines how records are used:

- **Gate.** The audit-clean field fails a session while an unresolved finding remains.
- **Signal.** The by-trust-ring breakdown feeds a SIEM as a per-session risk signal.
- **Lifecycle.** Findings carry severity, catalog references, and an SLA.

A record serves incident response (which component carried the payload, and
which controls were absent), vendor risk (which rings a vendor's inputs occupy),
and change management (a diff of records across a pipeline change).

## Confidentiality of the record

A record of what the model saw is itself sensitive. It inherits the
classification of the most sensitive component it describes. A component's
`content` block stores a digest instead of the text, but other fields, such as
`retrievalQuery`, can carry text. The digest of a short, low-entropy component,
such as a known system prompt or tool definition, can be reversed by dictionary.
Handle records with the same care as the content they describe. Version 0.3.0
has no field for a retention class or for digest salting.

## Catalog pins

Every mapping in a record targets pinned catalog versions under
`catalogVersions`: the OWASP Top 10 for LLM Applications 2026, the OWASP Top 10
for Agentic Applications 2026, CWE, and MITRE ATLAS. Each of the four carries a
content hash that a validator recomputes. CycloneDX appears as a pointer to the
parent specification.

## Honest absence

A record states what it could not observe instead of guessing:

- Rating fields accept `not-assessed`.
- `notCollected` lists field paths the emitter declined to assert.
- `illustrative` marks hand-authored records, so no one mistakes an example for measured output.

## Conformance

A conforming record validates against the schema at
`https://cxbom.org/schema/0.3.0/cxbom.schema.json`, and
`metadata.generatedBy.schema` names that URL. The schema file at that URL never
changes. A new schema version publishes at a new path.

## References

- CycloneDX Bill of Materials Standard, version 1.6 (ECMA-424). <https://cyclonedx.org/>
- OWASP Top 10 for LLM Applications, 2026 edition. <https://genai.owasp.org/>
- OWASP Top 10 for Agentic Applications, 2026. <https://genai.owasp.org/>
- Common Weakness Enumeration. <https://cwe.mitre.org/>
- MITRE ATLAS. <https://atlas.mitre.org/>
- JSON Schema, draft-07. <https://json-schema.org/>
- AgentRiskBOM, a preprint proposal for authority-envelope bills of materials, 2026.
