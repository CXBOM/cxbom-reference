# Context Bill of Materials

The film above is this recording. It is not a rate. A Context Bill of Materials (CxBOM) records everything assembled into an LLM
agent's context window before inference: each component, its trust ring, and
its provenance. It extends CycloneDX 1.6. This site publishes the
[specification](/spec/), the [JSON Schema](/schema/0.3.0/cxbom.schema.json), a
[field reference](/reference/), [example records](/examples/), and an offline
[record viewer](/viewer/).

The schema's identifier is `https://cxbom.org/schema/0.3.0/cxbom.schema.json`.
Validators can fetch it from that address.

## Privacy

This site sets no cookies, loads no third-party resources, and runs no
analytics. Server access logs are kept at the host's default retention and are
not examined.

## Contact

Write to [spec@cxbom.org](mailto:spec@cxbom.org).

## The reference session

The strip at the top of every page divides a reference session's context
window by trust ring, at true proportion. That session is not the session in
the film. The ledger below lists the same reference session one component per
row. A status of not assessed means the reference emitter did not measure a
runtime attack.
