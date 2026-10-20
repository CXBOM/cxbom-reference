# CxBOM schema changelog

Owner: ATACE Working Group.

## 0.3.0 (2026-10-18) — BREAKING

- Remove the model-level `attentionMechanism` and `tokenDemocracyApplies`
  fields and the session-level `dualFailureMultiplierAssessment` object. The
  schema records observable assembly facts only. The three property names
  asserted a model mechanism, not a recorded fact.
- Rewrite every schema description and comment that carried attention-mechanism
  or formal-result wording. The schema cites no numbered result from an earlier
  draft.
- The inversion finding's `formalRef` is empty. The template keeps its CWE and
  OWASP references.
- Rewrite the three example records against 0.3.0. The finance example records
  EchoLeak as an injection through retrieved content, not a workspace-
  configuration attack.
- `specVersion`, the `$id` version segment, `generatedBy.schema`, and
  `schema.cxbomVersion` move to 0.3.0 in lockstep. 0.2.0 stays in the tree and
  remains readable by the validator for the recorded takes and the ATACE copy.

## 0.2.0 (2026-07-12) — BREAKING

- Migrate OWASP mappings to the 2026 OWASP LLM Top 10 (by category name) and add
  the OWASP Agentic Top 10 (ASI) as a parallel dimension (`agenticCoverage` on
  control layers, `agenticRefs` on findings).
- Add required top-level `catalogVersions` (content-hashed catalog pins) and
  `illustrative` (boolean; true for hand-authored records, false for emitted).
- Honesty model: add a `not-assessed` enum member to the rating fields; add a
  per-component `notCollected[]` array; make unobservable sanitization fields
  (`scanner`, `scannerVersion`, `scannedAt`) optional; add `serverChecksum` /
  `contentSignature` companions so a trust-elevating integrity boolean can bind
  to a recomputable artifact.
- Constrain `content.sha256` and `documentSha256` to `^[0-9a-f]{64}$`.
- Add `sessionSummary.templateOverheadTokens` (the token-accounting model:
  `contextWindowTokensUsed = totalContextTokens + templateOverheadTokens`).
- Clarify that positional authority is pre-inference assembly salience, distinct
  from computational attention weight (Token Democracy). Scrub unsourced numeric
  risk thresholds from schema comments. Align terminology to the current framework name.

**Breaking:** a document valid under 0.1.0 that lacks `catalogVersions` /
`illustrative` does not validate under 0.2.0. `specVersion`, the `$id` version
segment, `generatedBy.schema`, and `schema.cxbomVersion` move to 0.2.0 in
lockstep.

## 0.1.0

- Initial CxBOM schema (superseded by 0.2.0).
