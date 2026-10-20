"""Schema and semantic checks for the three interface contracts.

Owner: ATACE Working Group.

Producers run these before writing a file. Consumers run them before rendering one.
A JSON Schema cannot express everything the contracts promise (ring shares that sum
to 1, Wilson intervals that match their counts, gap-free event sequences), so each
check_* function runs the schema first and then the rules a schema cannot state.
Every function returns a list of human-readable errors. An empty list is a pass.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

_HERE = Path(__file__).resolve().parent
# The repo root goes on sys.path so the strict parser is importable when this
# file runs from any directory. contracts/ imports only cxbom.jsonstrict and
# cxbom.timeutil, which have no dependencies beyond the standard library.
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

from cxbom import jsonstrict  # noqa: E402
from cxbom.timeutil import parse_time  # noqa: E402

_TOL = 0.001  # tolerance for floats written with three or four decimals
_MAX_LOCK_BYTES = 1024 * 1024
_MAX_SAFE_INT = 2**53


def _require_formats(checker: FormatChecker) -> None:
    # jsonschema skips "date-time" silently when its optional extra is not
    # installed, and every time in the C3 schemas would then pass unchecked.
    missing = [f for f in ("date-time", "uuid") if f not in checker.checkers]
    if missing:
        raise RuntimeError(
            f"jsonschema FormatChecker lacks {', '.join(missing)}. Install jsonschema[format] "
            "(rfc3339-validator provides date-time)")


def _validator(rel: str) -> Draft202012Validator:
    schema = json.loads((_HERE / rel).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    checker = FormatChecker()
    _require_formats(checker)
    return Draft202012Validator(schema, format_checker=checker)


_MEASUREMENT = _validator("measurement/measurement.schema.json")
_EVENT = _validator("events/event.schema.json")
_SIDECAR = _validator("events/sidecar-event.schema.json")
_LOCK2 = _validator("proxy/lockfile.schema.json")
_ATTEST = _validator("proxy/attestation-line.schema.json")


def _schema_errors(validator: Draft202012Validator, doc, where: str) -> list[str]:
    return [f"{where}{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}"
            for e in sorted(validator.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))]


def wilson(successes: int, trials: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score interval, the contract's required ciMethod."""
    p = successes / trials
    denom = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return max(0.0, center - half), min(1.0, center + half)


_ORDER = ("exploratory", "gatekept", "confirmatory")
_MASS = ("sink", "ring0", "ring1", "ring2")
_DETAIL = ("sink", "scaffold", "rule", "secret", "flood", "padding", "question", "toolScaffold",
           "generationPrompt")
_CELL = ("placement", "content", "defense", "span", "regime")

# C2 gate/decision pairing. gate_decision is a proxy event, and the proxy runs
# only in enforce or observe (cxbom.proxy has no "off" mode). The schema admits
# every decision under every gate, so the binding lives here:
#   off      no gate_decision at all. "off" means no lockfile checks and no
#            proxy, so nothing is gated (README C2; lab-j2 S2a).
#   observe  allow or would-block. Observe logs the block enforce would have
#            made, then forwards, so it never blocks (README C2: would-block
#            "only in a run whose run_started.gate is observe").
#   enforce  allow or block. Enforce blocks a mismatch and never logs a
#            would-block.
_GATE_DECISIONS = {"off": frozenset(),
                   "observe": frozenset({"allow", "would-block"}),
                   "enforce": frozenset({"allow", "block"})}


def _tag_errors(at: str, obj: dict, pilot: bool) -> list[str]:
    ev, ids = obj["evidence"], obj["hypothesisIds"]
    if pilot and ev != "exploratory":
        return [f"{at}: a pilot run may only carry exploratory evidence"]
    if ev == "exploratory" and ids:
        return [f"{at}: exploratory evidence carries no hypothesisIds"]
    if ev == "confirmatory" and (not ids or any(i.startswith("Q-") for i in ids)):
        return [f"{at}: confirmatory evidence needs Phi hypothesisIds (H1-H4)"]
    if ev == "gatekept" and (not ids or not all(i.startswith("Q-") for i in ids)):
        return [f"{at}: gatekept evidence needs Qwen hypothesisIds (Q-H1, Q-H2)"]
    return []


def _in(ci: list, x: float) -> bool:
    return ci[0] - _TOL <= x <= ci[1] + _TOL


def check_measurement(doc: dict) -> list[str]:
    errs = _schema_errors(_MEASUREMENT, doc, "measurement:")
    if errs:
        return errs
    run = doc["run"]
    pilot = run["kind"] == "pilot"
    if run["kind"] == "confirmatory" and run["preregistrationSha256"] is None:
        errs.append("run: a confirmatory run needs preregistrationSha256")
    names = [e["name"] for e in run["environment"]]
    if len(names) != len(set(names)):
        errs.append("run.environment: names must be unique")
    if doc["sinkBins"] != sorted(doc["sinkBins"]):
        errs.append("sinkBins: must be ascending")
    ladder = doc["ladder"]
    if not any(r["rung"] == "0" for r in ladder):
        errs.append("ladder: must include a rung 0 baseline")
    last: dict[tuple, int] = {}
    for r in ladder:
        key = tuple(r["cell"][k] for k in _CELL)
        at = f"ladder[{'/'.join(key)} rung {r['rung']}]"
        if r["rung"] != "R-ref" and r["shots"] != int(r["rung"]):
            errs.append(f"{at}: shots {r['shots']} does not match the rung")
        if key in last and r["shots"] <= last[key]:
            errs.append(f"{at}: shots must be strictly ascending within a cell")
        last[key] = r["shots"]
        quantities = {q: r[q] for q in ("attackSuccess", "primaryRuleShare", "attentionMass",
                                        "attentionMassDetail", "field") if q in r}
        for q, obj in quantities.items():
            errs += _tag_errors(f"{at}.{q}", obj, pilot)
            if q in ("attentionMass", "attentionMassDetail", "field") and obj["evidence"] != "exploratory":
                errs.append(f"{at}.{q}: descriptive quantities are exploratory")
        strongest = max((o["evidence"] for o in quantities.values()), key=_ORDER.index)
        ids = sorted({i for o in quantities.values() for i in o["hypothesisIds"]})
        if r["evidence"] != strongest or sorted(r["hypothesisIds"]) != ids:
            errs.append(f"{at}: entry evidence and hypothesisIds must summarize its quantities")
        for q, keys in (("attentionMass", _MASS), ("attentionMassDetail", _DETAIL)):
            total = sum(r[q][k] for k in keys)
            if abs(total - 1) > _TOL:
                errs.append(f"{at}: {q} must sum to 1 (softmax is a budget), got {total:.4f}")
        a = r["attackSuccess"]
        if a["successes"] > r["trials"]:
            errs.append(f"{at}: successes exceed trials")
        elif abs(a["rate"] - a["successes"] / r["trials"]) > _TOL:
            errs.append(f"{at}: rate {a['rate']} does not equal successes/trials")
        else:
            lo, hi = wilson(a["successes"], r["trials"])
            w = a["descriptiveWilson95"]
            if abs(w[0] - lo) > _TOL or abs(w[1] - hi) > _TOL:
                errs.append(f"{at}: descriptiveWilson95 {w} does not match the wilson interval "
                            f"[{lo:.4f}, {hi:.4f}]")
            if not _in(a["clusterCi95"], a["rate"]):
                errs.append(f"{at}: attackSuccess clusterCi95 does not contain the rate")
        s = r["primaryRuleShare"]
        if not _in(s["clusterCi95"], s["value"]):
            errs.append(f"{at}: primaryRuleShare clusterCi95 does not contain the value")
        if "field" in r:
            f = r["field"]
            if len(f["values"]) != f["rowCount"]:
                errs.append(f"{at}: field has {len(f['values'])} rows, rowCount says {f['rowCount']}")
            if any(b >= f["colCount"] for b in doc["sinkBins"]):
                errs.append(f"{at}: a sinkBins index is outside the field's columns")
            for i, row in enumerate(f["values"]):
                if len(row) != f["colCount"]:
                    errs.append(f"{at}: field row {i} has {len(row)} columns, colCount says {f['colCount']}")
                elif abs(sum(row) - 1) > _TOL:
                    errs.append(f"{at}: field row {i} sums to {sum(row):.4f}, expected 1")
    return errs


def check_events(events: list[dict]) -> list[str]:
    errs: list[str] = []
    for i, ev in enumerate(events):
        errs += _schema_errors(_EVENT, ev, f"event[{i}]:")
    if errs:
        return errs
    if not events:
        return ["events: stream is empty"]
    if events[0]["type"] != "run_started":
        errs.append("events: the first event must be run_started")
    if events[-1]["type"] != "run_finished":
        errs.append("events: the last event must be run_finished")
    run = events[0]["run"]
    for i, ev in enumerate(events):
        if ev["seq"] != i:
            errs.append(f"event[{i}]: seq {ev['seq']} breaks the gap-free sequence (expected {i})")
            break
    for i, ev in enumerate(events):
        if ev["run"] != run:
            errs.append(f"event[{i}]: run id {ev['run']!r} differs from {run!r}")
        if i and ev["t"] < events[i - 1]["t"]:
            errs.append(f"event[{i}]: time goes backwards ({ev['t']} < {events[i - 1]['t']})")
        # An exactly empty caption is a hold: the beat shows no narration
        # (take_setup's s3-reveal-hold). The schema allows it and the Jetson
        # emits it as is. A caption of only whitespace is still refused, since
        # it would render as a blank line where a hold renders as nothing.
        if ev["type"] == "beat" and ev["data"]["caption"] and not ev["data"]["caption"].strip():
            errs.append(f"event[{i}]: beat caption is whitespace only (an empty caption is a hold)")
        if (ev["prev_sha256"] is None) != (ev["seq"] == 0):
            errs.append(f"event[{i}]: prev_sha256 must be null only at seq 0")
        # JSON Schema's "integer" accepts a zero-fraction float, so 0.0 passes
        # the exitCode bounds. The terminal pane would then print "0.0" where
        # the file-derived pane prints "0". Refused in C3's words.
        if ev["type"] == "proxy_exited" and type(ev["data"]["exitCode"]) is not int:
            errs.append(f"event[{i}]: exitCode must be an integer, not a float or bool")
    # C2 1.3.0: the attestation pane mirrors one C3 log per proxy session, so
    # its sequence follows C3's rule. A session line has no seq (C3 2.0.0
    # starts seq at 1 on the line after it), and later lines are contiguous
    # from 1.
    #
    # Contiguity is per log, not per server, because C3 writes one log per
    # proxy session and a take that restarts a proxy against the same server
    # opens a second one whose seq starts over at 1. The session line is where
    # that happens and is the only marker of a new proxySessionId the merged
    # stream carries, since attestation_appended.data holds the C3 line's hash
    # and not its payload. check_sidecar_events already tracks localSeq per
    # proxySessionId for the same restart (S4), so the two layers agree.
    # Strictness inside one log is unchanged: a gap after a session line still
    # fails.
    attest_seq: dict[str, int] = {}
    session_sha: dict[str, set[str]] = {}
    for i, ev in enumerate(events):
        if ev["type"] != "attestation_appended":
            continue
        sid, seq, kind = ev["data"]["serverId"], ev["data"]["seq"], ev["data"]["kind"]
        if (kind == "session") != (seq is None):
            errs.append(f"event[{i}]: a session line has a null seq and every other line has one")
            continue
        if seq is None:
            # kind is "session" here, guaranteed by the check above. It opens a
            # new log for this server, so the count starts over.
            #
            # Two session lines for one server must differ. A genuine second
            # log has a different session line: C3 mints a fresh proxySessionId
            # per writer (cxbom.attestation.AttestationWriter) and records
            # startedAt and pid, so its bytes and this hash differ. A repeated
            # session hash is one log written into the stream twice, and
            # nothing else here catches it. The seq restart is legal, the
            # agreement check sees one log per slice under the cadence the J2
            # spec prescribes, and the payload is not in the event to compare
            # against the file. Session lines only: two restarts inside one
            # second write byte-identical protocol and server lines, whose at
            # is second-resolution, so a rule over every line would refuse a
            # legal pair of logs.
            sha = ev["data"]["sha256"]
            seen = session_sha.setdefault(sid, set())
            if sha in seen:
                errs.append(f"event[{i}]: the session line for {sid} repeats an earlier session "
                            "line's sha256, so the stream carries one attestation log twice "
                            "rather than a restart")
            seen.add(sha)
            attest_seq.pop(sid, None)
            continue
        # Same float hole as exitCode, and worse here: 1.0 == 1, so contiguity
        # below and check_attestation_agreement's comparison would both accept
        # a float that renders as "1.0" beside the log's "1". C3's
        # check_attestation refuses it outright, so this mirrors its wording.
        if type(seq) is not int:
            errs.append(f"event[{i}]: attestation seq must be an integer, not a float or bool")
            continue
        expected = attest_seq.get(sid, 0) + 1
        if seq != expected:
            errs.append(f"event[{i}]: attestation seq {seq} for {sid} is not contiguous "
                        f"(expected {expected})")
        attest_seq[sid] = seq
    # C2 gate/decision/outcome pairing (schema-valid by here, so gate, decision
    # and outcome are all enum members). The gate is the run's declared
    # enforcement mode; every gate_decision must pair with it, and "blocked" is
    # the one outcome a gate other than enforce cannot produce.
    gate = next((ev["data"]["gate"] for ev in events if ev["type"] == "run_started"), None)
    if gate is not None:
        allowed = _GATE_DECISIONS[gate]
        for i, ev in enumerate(events):
            if ev["type"] != "gate_decision" or ev["data"]["decision"] in allowed:
                continue
            decision = ev["data"]["decision"]
            if gate == "off":
                # off runs no proxy, so any gate_decision is spurious, whatever
                # its value. Naming the value would hide that the whole event
                # class is impossible here, not just this one decision.
                errs.append(f"event[{i}]: gate_decision under gate 'off' is impossible: off "
                            "runs no lockfile checks and no proxy, so no tool is gated")
            else:
                errs.append(f"event[{i}]: decision {decision!r} does not pair with gate "
                            f"{gate!r}, which allows {sorted(allowed)}")
        # "blocked" means the gate stopped the item before the model saw it, and
        # only enforce does that: observe forwards after logging a would-block,
        # and off never checks. So a run ends "blocked" only under enforce; under
        # observe or off the same take ends exfiltrated, no-attack, or aborted.
        for i, ev in enumerate(events):
            if ev["type"] == "run_finished" and ev["data"]["outcome"] == "blocked" \
                    and gate != "enforce":
                errs.append(f"event[{i}]: outcome 'blocked' requires gate 'enforce', not "
                            f"{gate!r}: only enforce blocks a mismatch")
    errs += _check_record_facts(events)
    return errs


def _check_record_facts(events: list[dict]) -> list[str]:
    """C2 1.4.0 cross-checks on the optional record facts (schema-valid by here).

    An inference is the run of component_assembled events that ends at the next
    cxbom_emitted, so a finding may name only components from its own run. A
    finding that names a real component of another inference would otherwise
    pass and put the wrong evidence in the S3 panel.
    """
    errs: list[str] = []
    assembled: set[str] = set()
    for ev in events:
        data = ev["data"]
        if ev["type"] == "component_assembled":
            assembled.add(data["componentId"])
        elif ev["type"] == "cxbom_emitted":
            if any(not set(f["affectedComponents"]) <= assembled for f in data.get("findings", [])):
                errs.append("cxbom_emitted: a finding names a component its inference did not assemble")
            if data.get("templateOverheadTokens", 0) > data.get("contextWindowTokensUsed", float("inf")):
                errs.append("cxbom_emitted: templateOverheadTokens is above contextWindowTokensUsed")
            assembled = set()
    return errs


def check_events_text(text: str) -> list[str]:
    """Verify the prev_sha256 chain over raw lines, then validate the parsed events.

    The chain covers exact bytes, so it must be checked before parsing
    discards the original serialization (whitespace, key order, and so on).
    Lines parse with cxbom.jsonstrict. Never raises.
    """
    if not isinstance(text, str):
        return ["events: text must be a str"]
    if not text.endswith("\n"):
        return ["events: text must end with a trailing newline"]
    body = text[:-1]
    try:
        # Confirms every line is encodable up front, so the per-line hashing
        # below can never raise on a lone surrogate smuggled into a string.
        body.encode("utf-8")
    except UnicodeEncodeError:
        return ["events: text is not valid UTF-8"]
    lines = body.split("\n")
    errs: list[str] = []
    parsed: list[dict] = []
    for i, line in enumerate(lines):
        try:
            # Strict parsing: NaN, Infinity, and duplicate keys would let the
            # dashboard and the collector read one line two different ways.
            obj = jsonstrict.to_python(jsonstrict.parse(line.encode("utf-8")))
        except jsonstrict.StrictJSONError as e:
            errs.append(f"event[{i}]: not strict JSON ({e})")
            continue
        if not isinstance(obj, dict):
            errs.append(f"event[{i}]: line is not a JSON object")
            continue
        if i > 0:
            expected = hashlib.sha256(lines[i - 1].encode("utf-8")).hexdigest()
            if obj.get("prev_sha256") != expected:
                errs.append(f"event[{i}]: prev_sha256 does not match line {i - 1}")
        parsed.append(obj)
    errs += check_events(parsed)
    return errs


def check_sidecar_events(events: list[dict]) -> list[str]:
    errs: list[str] = []
    for i, ev in enumerate(events):
        errs += _schema_errors(_SIDECAR, ev, f"sidecar[{i}]:")
    if errs:
        return errs
    # Sessions interleave in one sidecar file, so localSeq contiguity is
    # tracked per proxySessionId rather than between adjacent lines. A
    # launch_refused line has no proxy session (its proxySessionId is null,
    # enforced by the schema), because it is written before a session opens
    # (C2 1.2.0, spec 8.1). Any number of them may appear anywhere in one
    # sidecar file, since a demo can restart the proxy against the same
    # --events path after a refusal (S4): each is self-contained at localSeq
    # 0 and takes no part in this bookkeeping, so it is skipped here rather
    # than tracked under the key None.
    last_seq: dict[str, int] = {}
    for i, ev in enumerate(events):
        sid, seq = ev["proxySessionId"], ev["localSeq"]
        if sid is None:
            continue
        if sid not in last_seq:
            if seq != 0:
                errs.append(f"sidecar[{i}]: first event of session {sid} has localSeq {seq}, expected 0")
        elif seq != last_seq[sid] + 1:
            errs.append(f"sidecar[{i}]: localSeq gap within one proxy session")
        last_seq[sid] = seq
    return errs


def _strict_loads(text: str, max_bytes: int):
    """Parse text with cxbom.jsonstrict. Raises StrictJSONError or UnicodeEncodeError."""
    return jsonstrict.to_python(jsonstrict.parse(text.encode("utf-8"), max_bytes=max_bytes))


def _unsafe_int(obj) -> bool:
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
        elif isinstance(cur, int) and not isinstance(cur, bool) and abs(cur) > _MAX_SAFE_INT:
            return True
    return False


def check_lock2_text(text: str) -> list[str]:
    """Check a lock's text: strict JSON, schema, canonical form, envelope binding.

    The envelope binding is checked for every server in the lock. The library
    (cxbom.lockfile.verified_entry) checks only the server it was asked for.
    """
    if not isinstance(text, str):
        return ["lock: text must be a str"]
    try:
        doc = _strict_loads(text, _MAX_LOCK_BYTES)
    except UnicodeEncodeError:
        return ["lock: text is not valid UTF-8"]
    except jsonstrict.StrictJSONError as e:
        return [f"lock: not strict JSON ({e})"]
    if _unsafe_int(doc):
        return ["lock: holds an integer beyond 2**53"]
    errs = _schema_errors(_LOCK2, doc, "lock:")
    if text != json.dumps(doc, indent=2, sort_keys=True) + "\n":
        errs.append("lock: not in canonical form (indent 2, sorted keys, trailing newline)")
    if errs:
        return errs
    for sid, srv in doc["servers"].items():
        env = srv["envelope"]
        if env["serverId"] != sid:
            errs.append(f"lock: servers/{sid}: envelope serverId {env['serverId']!r} differs from its key")
        if env["lockScope"] != doc["lockScope"]:
            errs.append(f"lock: servers/{sid}: envelope lockScope differs from the lock's lockScope")
    return errs


def _parse_at(s: str) -> datetime:
    # One RFC 3339 grammar for the library and the checker, independent of
    # the Python version's fromisoformat.
    return parse_time(s)


def check_attestation(lines: list[dict]) -> list[str]:
    if not lines:
        return ["attestation: log is empty"]
    errs: list[str] = []
    for i, line in enumerate(lines):
        errs += _schema_errors(_ATTEST, line, f"attestation[{i}]:")
    if errs:
        return errs
    if lines[0]["kind"] != "session":
        return ["attestation: first line must be session"]
    if type(lines[0].get("pid")) is not int:
        errs.append("attestation[0]: pid must be an integer, not a float or bool")
    prev_at: datetime | None = None
    for i, line in enumerate(lines[1:], start=1):
        if line["kind"] == "session":
            errs.append(f"attestation[{i}]: second session line")
            break
        if type(line["seq"]) is not int:
            errs.append(f"attestation[{i}]: seq must be an integer, not a float or bool")
            break
        if line["seq"] != i:
            errs.append(f"attestation[{i}]: seq {line['seq']} breaks contiguity (expected {i})")
            break
        try:
            cur_at = _parse_at(line["at"])
        except ValueError:
            errs.append(f"attestation[{i}]: time {line['at']!r} does not parse")
            break
        if prev_at is not None and cur_at < prev_at:
            errs.append(f"attestation[{i}]: time {line['at']} is before the previous line's time")
        prev_at = cur_at
        if line["kind"] == "end" and i != len(lines) - 1:
            errs.append("attestation: lines after end")
    return errs


def _pane_key(kind, seq, sha256: str) -> tuple:
    """Key one attestation line for the two-source comparison.

    The seq's type name is part of the key because Python's 1 == 1.0. A float
    seq on one side and an int on the other would compare equal here while the
    two panes render "1.0" and "1", which is the divergence the comparison
    exists to catch. check_events and check_attestation both refuse a float
    seq before this runs; the type in the key keeps that from being the only
    thing standing between the two panes.
    """
    return (kind, type(seq).__name__, seq, sha256)


def check_attestation_agreement(log_text: str, events: list[dict]) -> list[str]:
    """The attestation pane has two sources for one take, and they must agree.

    The dashboard reads a run bundle's C3 attestation log when it replays a
    recorded take, and the C2 1.3.0 attestation_appended events when it
    follows a live one. Both panes claim to show the same history, so a take
    that carries both must carry the same lines in both: same server, same
    count, same kinds in the same order, same sequence numbers, and the same
    per-line content hash. The summary is prose written for the pane and is
    not compared.

    The hash is what makes this a real check rather than a shape check. C3
    kind sequences are stereotyped (session, protocol, server, verdict, end),
    so two different takes of the same server agree on kind and seq as a
    matter of course. Without the hash, a pane built from take B certifies as
    agreeing with take A's log.

    Takes the log's text rather than its parsed lines, because
    attestation_appended.sha256 is taken over the line's bytes as written and
    a re-serialization cannot stand in for them (cxbom.attestation encodes
    with ensure_ascii=False, so a non-ASCII value round-trips to different
    bytes through json.dumps's default).

    Takes the log for one server. The events may carry other servers' lines,
    which are ignored here and checked against their own logs.

    Takes one log, so a take that restarts a proxy against the same server
    passes each of its logs with that log's slice of the stream. C3 writes one
    log per proxy session and check_events allows the restart, so the slice
    boundary is the session line. Handed the whole stream for such a take, this
    says so rather than reporting a line-count difference the caller would read
    as the two panes disagreeing.
    """
    raw, lines, errs = _frame_attestation(log_text)
    errs = [f"agreement: {e}" for e in errs]
    if not errs:
        errs += [f"agreement: {e}" for e in check_attestation(lines)]
    errs += [f"agreement: {e}" for e in check_events(events)]
    if errs:
        return errs
    server = lines[0]["serverId"]
    pane = [ev for ev in events
            if ev["type"] == "attestation_appended" and ev["data"]["serverId"] == server]
    logs = sum(1 for ev in pane if ev["data"]["kind"] == "session")
    if logs > 1:
        return [f"agreement: the stream carries {logs} attestation logs for {server}, so it "
                "covers more than one proxy session. Call this once per log, with that log's "
                "events."]
    if len(pane) != len(lines):
        return [f"agreement: the log for {server} has {len(lines)} lines and the stream has "
                f"{len(pane)}"]
    for i, (rawline, line, ev) in enumerate(zip(raw, lines, pane)):
        # A C3 session line carries no seq at all, and the event says so with
        # null. The hash covers the line's bytes without the framing newline,
        # the same convention C2's own prev_sha256 chain uses.
        want = _pane_key(line["kind"], line.get("seq"), hashlib.sha256(rawline).hexdigest())
        got = _pane_key(ev["data"]["kind"], ev["data"]["seq"], ev["data"]["sha256"])
        if want != got:
            errs.append(f"agreement: line {i} of {server} is {want[0]}/{want[2]}/{want[3]} in the "
                        f"log and {got[0]}/{got[2]}/{got[3]} in the stream")
    return errs


def _is_attestation_io_end(raw: bytes) -> bool:
    try:
        obj = jsonstrict.to_python(jsonstrict.parse(raw))
    except jsonstrict.StrictJSONError:
        return False
    return isinstance(obj, dict) and obj.get("kind") == "end" and obj.get("reason") == "attestation-io"


def _frame_attestation(text: str) -> tuple[list[bytes], list, list[str]]:
    """Frame and parse an attestation log's text like attestation.read_log.

    Framing rules: a final line with no trailing newline is a partial write
    and is ignored. An empty complete line is an error. Exactly one
    unparseable line is tolerated, and only when it is immediately followed
    by the log's final line and that line is end with reason attestation-io
    (the writer's recovery record after a short write). Lines parse with
    cxbom.jsonstrict, so duplicate keys and NaN are errors. Never raises.

    Returns the bytes of each line that parsed, without its framing newline,
    alongside the parsed objects and the framing errors. The bytes come back
    because C2 1.3.0's attestation_appended.sha256 is taken over them, and
    only the reader that framed the file still has them.
    """
    if not isinstance(text, str):
        return [], [], ["attestation: text must be a str"]
    try:
        data = text.encode("utf-8")
    except UnicodeEncodeError:
        return [], [], ["attestation: text is not valid UTF-8"]
    complete = data.split(b"\n")[:-1]
    n = len(complete)
    raw_lines: list[bytes] = []
    lines: list = []
    errs: list[str] = []
    i = 0
    while i < n:
        raw = complete[i]
        if raw == b"":
            errs.append(f"attestation: line {i + 1}: empty line")
            break
        try:
            lines.append(jsonstrict.to_python(jsonstrict.parse(raw)))
        except jsonstrict.StrictJSONError as e:
            if i == n - 2 and _is_attestation_io_end(complete[i + 1]):
                i += 1
                continue
            errs.append(f"attestation: line {i + 1}: {e}")
            break
        raw_lines.append(raw)
        i += 1
    return raw_lines, lines, errs


def check_attestation_text(text: str) -> list[str]:
    """Frame and parse an attestation log's text like attestation.read_log, then check it.

    Framing rules are in _frame_attestation. Never raises.
    """
    _, lines, errs = _frame_attestation(text)
    if errs:
        return errs
    return check_attestation(lines)
