"""Contract examples validate, and each semantic check fires on a broken copy.

Owner: ATACE Working Group.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "contracts"))
import checks  # noqa: E402

C = ROOT / "contracts"
MEASUREMENT = json.loads((C / "measurement/example.measurement.json").read_text())
EVENTS = [json.loads(ln) for ln in (C / "events/example-rug-pull-gate-on.events.jsonl").read_text().splitlines()]
LOCK_TEXT = (C / "proxy/example.cxbom.lock").read_text()
ATTEST = [json.loads(ln) for ln in (C / "proxy/example.attestation.jsonl").read_text().splitlines()]


def test_examples_pass_schema_and_semantics():
    assert checks.check_measurement(MEASUREMENT) == []
    assert checks.check_events(EVENTS) == []
    assert checks.check_lock2_text(LOCK_TEXT) == []


def test_measurement_schema_rejects_hostname_style_hardware():
    doc = copy.deepcopy(MEASUREMENT)
    doc["run"]["hardware"] = "Jensen.local"
    assert checks.check_measurement(doc)


def test_measurement_rejects_a_1_x_document():
    doc = copy.deepcopy(MEASUREMENT)
    doc["contract"]["version"] = "1.0.0"
    assert any("version" in e for e in checks.check_measurement(doc))


def test_measurement_accepts_the_r_ref_rung():
    doc = copy.deepcopy(MEASUREMENT)
    doc["ladder"][1].update(rung="R-ref", shots=1400)
    assert checks.check_measurement(doc) == []


@pytest.mark.parametrize("mutate, needle", [
    (lambda d: d["ladder"].__setitem__(slice(0, 2), d["ladder"][1::-1]), "strictly ascending"),
    (lambda d: d["ladder"][1].update(shots=9), "does not match the rung"),
    (lambda d: d["ladder"].pop(0), "rung 0"),
    (lambda d: d["ladder"][0]["attentionMass"].update(ring0=0.9), "attentionMass must sum"),
    (lambda d: d["ladder"][0]["attentionMassDetail"].update(rule=0.5), "attentionMassDetail must sum"),
    (lambda d: d["ladder"][0]["attackSuccess"].update(rate=0.5), "rate"),
    (lambda d: d["ladder"][1]["attackSuccess"].update(descriptiveWilson95=[0.1, 0.2]), "wilson"),
    (lambda d: d["ladder"][1]["attackSuccess"].update(clusterCi95=[0.5, 0.6]), "does not contain the rate"),
    (lambda d: d["ladder"][1]["primaryRuleShare"].update(clusterCi95=[0.5, 0.6]), "does not contain the value"),
    (lambda d: d["ladder"][3]["attackSuccess"].update(hypothesisIds=["H2"]), "exploratory evidence carries no"),
    (lambda d: d["ladder"][1]["primaryRuleShare"].update(hypothesisIds=[]), "confirmatory evidence needs"),
    (lambda d: d["ladder"][3]["attackSuccess"].update(evidence="gatekept", hypothesisIds=["H1"]), "gatekept"),
    (lambda d: d["ladder"][1]["attentionMass"].update(evidence="confirmatory", hypothesisIds=["H1"]), "descriptive"),
    (lambda d: d["ladder"][1].update(evidence="exploratory"), "summarize"),
    (lambda d: d["run"].update(kind="pilot"), "pilot run may only"),
    (lambda d: d["run"].update(preregistrationSha256=None), "preregistrationSha256"),
])
def test_measurement_semantic_checks_fire(mutate, needle):
    doc = copy.deepcopy(MEASUREMENT)
    mutate(doc)
    errs = checks.check_measurement(doc)
    assert any(needle in e for e in errs), errs


def test_measurement_example_matches_its_generator():
    # contracts/proxy/make_example.py shares its module basename with this
    # file. Loading by path, under a distinct module name, keeps this test
    # from clobbering sys.modules["make_example"] that test_lockfile.py's
    # trusted_example fixture depends on.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "cxbom_measurement_make_example", C / "measurement" / "make_example.py")
    meas_example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(meas_example)
    assert meas_example.build() == MEASUREMENT


def test_measurement_defense_na_for_non_h3_cells():
    # Controller ruling R4: cell.defense carries "NA" for every cell outside
    # the H3 (DOC x {NONE, L1, L2}) rung. None of the example's ladder
    # entries is the H3 cell, so every one of them must read "NA", and the
    # schema must accept it while still rejecting an unknown value.
    doc = copy.deepcopy(MEASUREMENT)
    # Positive control: all() over an empty ladder is vacuously true, so a
    # fixture that lost its ladder would pass the assert below without this
    # gate ever running against a single cell.
    assert doc["ladder"], "MEASUREMENT has no ladder entries; the all() below would pass vacuously"
    assert all(r["cell"]["defense"] == "NA" for r in doc["ladder"])
    assert checks.check_measurement(doc) == []
    doc["ladder"][0]["cell"]["defense"] = "L3"
    assert checks.check_measurement(doc)


@pytest.mark.parametrize("mutate, needle", [
    (lambda ev: ev.pop(3), "seq"),
    (lambda ev: ev[5].update(t=0.0), "time"),
    (lambda ev: ev.pop(0), "run_started"),
    (lambda ev: ev.pop(), "run_finished"),
    (lambda ev: ev[4].update(run="other-run"), "run id"),
    (lambda ev: ev[1]["data"].update(caption="  "), "caption"),
])
def test_event_semantic_checks_fire(mutate, needle):
    ev = copy.deepcopy(EVENTS)
    mutate(ev)
    # Re-number after a removal so each case isolates one defect, except the seq case.
    if needle != "seq":
        for i, e in enumerate(ev):
            e["seq"] = i
    errs = checks.check_events(ev)
    assert any(needle in e for e in errs), errs


def test_event_schema_rejects_unknown_type():
    ev = copy.deepcopy(EVENTS)
    ev[2]["type"] = "tool_exploded"
    assert checks.check_events(ev)


def test_lock2_example_passes():
    assert checks.check_lock2_text(LOCK_TEXT) == []


def test_lock2_example_is_reproducible_and_signed():
    sys.path.insert(0, str(ROOT / "contracts" / "proxy"))
    import make_example
    lock_text, pub_text = make_example.build()
    assert lock_text == LOCK_TEXT
    assert pub_text == (C / "proxy/example-key.pub").read_text()
    from cxbom.signing import PublicKey, decode_pub, fingerprint, verify_obj
    raw = decode_pub(pub_text.strip())
    lock = json.loads(lock_text)
    srv = lock["servers"]["fetch"]
    assert verify_obj(PublicKey(fingerprint(raw), raw), srv["envelope"], srv["signature"]["sig"])


@pytest.mark.parametrize("mutate, needle", [
    (lambda d: d.update(lockScope="abc"), "lockScope"),
    (lambda d: d["servers"]["fetch"]["envelope"].update(serverId="other"), "serverId"),
    (lambda d: d["servers"]["fetch"]["envelope"].update(lockScope="1" * 32), "lockScope"),
    (lambda d: d["servers"]["fetch"]["envelope"]["entry"].update(files={"../x": "0" * 64}), "files"),
    (lambda d: d["servers"]["fetch"]["envelope"]["entry"]["eras"]["legacy"]["tools"]["fetch"].update(approvedBy="a;b"), "approvedBy"),
])
def test_lock2_rules(mutate, needle):
    d = json.loads(LOCK_TEXT)
    mutate(d)
    errs = checks.check_lock2_text(json.dumps(d, indent=2, sort_keys=True) + "\n")
    assert any(needle in e for e in errs), errs


def test_format_checks_are_active():
    d = json.loads(LOCK_TEXT)
    d["servers"]["fetch"]["envelope"]["issuedAt"] = "yesterday"
    errs = checks.check_lock2_text(json.dumps(d, indent=2, sort_keys=True) + "\n")
    assert any("issuedAt" in e for e in errs), errs


def test_attestation_example_passes():
    assert checks.check_attestation(ATTEST) == []


def test_attestation_rejects_unknown_verdict():
    bad = [dict(l) for l in ATTEST]
    bad[2]["verdict"] = "looks-fine"
    assert checks.check_attestation(bad)


def test_attestation_empty_log():
    assert checks.check_attestation([]) == ["attestation: log is empty"]


# --- Fix round 1 ---


def test_attestation_rejects_second_session_line():
    lines = [dict(l) for l in ATTEST[:2]] + [dict(ATTEST[0])]
    errs = checks.check_attestation(lines)
    assert any("second session line" in e for e in errs), errs


def test_attestation_flags_lines_after_end():
    lines = [dict(l) for l in ATTEST]
    tail = dict(ATTEST[1])  # reuse a valid protocol line as a stand-in trailing record
    tail["seq"] = ATTEST[-1]["seq"] + 1
    tail["at"] = "2026-10-10T18:08:00Z"
    lines.append(tail)
    errs = checks.check_attestation(lines)
    assert any("lines after end" in e for e in errs), errs


def test_attestation_flags_reordered_lines():
    lines = [dict(l) for l in ATTEST]
    lines[1], lines[2] = lines[2], lines[1]  # swap without renumbering: seq order breaks
    errs = checks.check_attestation(lines)
    assert errs


def test_attestation_flags_missing_session_first_line():
    lines = [dict(ATTEST[1])]
    errs = checks.check_attestation(lines)
    assert any("session" in e for e in errs), errs


def test_attestation_rejects_offset_time():
    lines = [dict(l) for l in ATTEST]
    lines[1]["at"] = "2026-10-10T18:05:01+00:00"
    errs = checks.check_attestation(lines)
    assert errs


def test_attestation_rejects_backwards_time():
    lines = [dict(l) for l in ATTEST]
    lines[3]["at"] = "2026-10-10T18:00:00Z"  # earlier than the line before it
    errs = checks.check_attestation(lines)
    assert any("time" in e for e in errs), errs


def test_attestation_rejects_float_seq():
    lines = [dict(l) for l in ATTEST]
    lines[1]["seq"] = 1.0
    errs = checks.check_attestation(lines)
    assert any("seq" in e for e in errs), errs


def test_attestation_rejects_float_pid():
    lines = [dict(ATTEST[0], pid=4242.0)]
    errs = checks.check_attestation(lines)
    assert any("pid" in e for e in errs), errs


def test_attestation_rejects_path_traversal_server_id():
    lines = [dict(l) for l in ATTEST]
    lines[0] = dict(lines[0], serverId="../escape")
    errs = checks.check_attestation(lines)
    assert errs


def test_attestation_rejects_wrong_contract_version():
    lines = [dict(l) for l in ATTEST]
    lines[0] = dict(lines[0], contract={"name": "cxbom-attestation", "version": "1.0.0"})
    errs = checks.check_attestation(lines)
    assert errs


# --- Task 12: C2 1.1.0, sidecar events, and the prev_sha256 chain ---


def test_event_example_is_reproducible():
    # contracts/proxy/make_example.py shares its module basename with this
    # file. Loading by path, under a distinct module name, keeps this test
    # from clobbering sys.modules["make_example"] that test_lockfile.py's
    # trusted_example fixture depends on.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "cxbom_events_make_example", C / "events" / "make_example.py")
    ev_example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ev_example)
    assert ev_example.build() == (C / "events/example-rug-pull-gate-on.events.jsonl").read_text()


def test_proxy_never_answers_an_unissued_agent_id():
    issued = {e["data"]["rpcId"] for e in EVENTS
              if e["type"] == "mcp_message" and e["data"]["from"] == "agent"}
    answered = {e["data"]["rpcId"] for e in EVENTS
                if e["type"] == "mcp_message" and e["data"]["from"] == "proxy" and e["data"]["to"] == "agent"
                and e["data"]["rpcId"] is not None}
    assert answered <= issued


def test_sidecar_schema():
    good = {"v": 1, "at": "2026-10-10T18:00:00Z", "mono": 1.5,
            "proxySessionId": "3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11", "localSeq": 0,
            "type": "gate_decision",
            "data": {"serverId": "fetch", "tool": "fetch", "decision": "block", "reason": "hash differs"}}
    assert checks.check_sidecar_events([good]) == []
    assert checks.check_sidecar_events([dict(good, type="cxbom_emitted")])


def test_events_text_example_passes():
    text = (C / "events/example-rug-pull-gate-on.events.jsonl").read_text()
    assert checks.check_events_text(text) == []


def test_events_text_chain_break_reports_next_event():
    text = (C / "events/example-rug-pull-gate-on.events.jsonl").read_text()
    lines = text[:-1].split("\n")
    # A one-byte change inside line 3's summary text stays valid JSON and does
    # not disturb any other semantic check, isolating the chain-break signal.
    lines[3] = lines[3].replace("proxy forwards the request", "proxy forwards the requesu")
    mutated = "\n".join(lines) + "\n"
    errs = checks.check_events_text(mutated)
    assert any("event[4]" in e and "prev_sha256" in e for e in errs), errs


def test_events_text_requires_trailing_newline():
    text = (C / "events/example-rug-pull-gate-on.events.jsonl").read_text()
    assert checks.check_events_text(text.rstrip("\n"))


def test_events_text_reports_json_parse_error_without_raising():
    errs = checks.check_events_text("not json\n")
    assert errs


@pytest.mark.parametrize("mutate, needle", [
    (lambda ev: ev[0].update(prev_sha256="0" * 64), "prev_sha256"),
    (lambda ev: ev[1].update(prev_sha256=None), "prev_sha256"),
])
def test_event_prev_sha256_nullness_enforced(mutate, needle):
    ev = copy.deepcopy(EVENTS)
    mutate(ev)
    errs = checks.check_events(ev)
    assert any(needle in e for e in errs), errs


def test_run_started_gate_rejects_old_value():
    ev = copy.deepcopy(EVENTS)
    ev[0]["data"]["gate"] = "on"
    assert checks.check_events(ev)


def test_run_started_requires_demonstration():
    ev = copy.deepcopy(EVENTS)
    del ev[0]["data"]["demonstration"]
    assert checks.check_events(ev)


def test_attention_frame_sink_and_evidence_pass_schema():
    ev = copy.deepcopy(EVENTS)
    frame = {
        "v": 1, "t": ev[0]["t"], "run": ev[0]["run"], "type": "attention_frame",
        "data": {"shots": 0, "ring0": 0.4, "ring1": 0.3, "ring2": 0.3, "ladderIndex": 0,
                 "sink": {"kind": "canary"}, "evidence": {"span": [0, 10]}},
        "prev_sha256": "a" * 64,
    }
    ev.insert(1, frame)
    for i, e in enumerate(ev):
        e["seq"] = i
    assert checks.check_events(ev) == []


def test_sidecar_schema_invalid_event_returns_errors_without_raising():
    errs = checks.check_sidecar_events([{"v": 1}])
    assert errs


def test_sidecar_local_seq_gap_reported():
    base = {"v": 1, "at": "2026-10-10T18:00:00Z", "mono": 1.5,
            "proxySessionId": "3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11", "localSeq": 0,
            "type": "gate_decision",
            "data": {"serverId": "fetch", "tool": "fetch", "decision": "block", "reason": "hash differs"}}
    gapped = dict(base, localSeq=2, mono=2.5)
    errs = checks.check_sidecar_events([base, gapped])
    assert any("localSeq gap" in e for e in errs), errs


# --- Task 12 fix round 1: non-object lines, invalid UTF-8, interleaved sidecars ---


@pytest.mark.parametrize("bad_json", ["42", "[]", '"x"', "null"])
def test_events_text_non_object_line_reported_without_raising(bad_json):
    text = (C / "events/example-rug-pull-gate-on.events.jsonl").read_text()
    lines = text[:-1].split("\n")
    lines[1] = bad_json  # index >= 1, so the chain check would try obj.get(...) on it
    mutated = "\n".join(lines) + "\n"
    errs = checks.check_events_text(mutated)
    assert any("event[1]: line is not a JSON object" in e for e in errs), errs


def test_events_text_rejects_invalid_utf8_without_raising():
    text = (C / "events/example-rug-pull-gate-on.events.jsonl").read_text()
    # A lone surrogate is a valid Python str character but cannot be encoded
    # to UTF-8, which is what a real sidecar or merged-stream file would be.
    bad = text[:-1] + "\ud800" + "\n"
    errs = checks.check_events_text(bad)
    assert errs == ["events: text is not valid UTF-8"]


_SID_A = "3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11"
_SID_B = "6e6a708e-1f9d-4c2a-8b3e-9a0f1c7d2e55"


def _sidecar(sid: str, seq: int, mono: float) -> dict:
    return {"v": 1, "at": "2026-10-10T18:00:00Z", "mono": mono,
            "proxySessionId": sid, "localSeq": seq, "type": "gate_decision",
            "data": {"serverId": "fetch", "tool": "fetch", "decision": "block", "reason": "hash differs"}}


def test_sidecar_interleaved_sessions_report_only_the_gapped_one():
    events = [
        _sidecar(_SID_A, 0, 0.0),
        _sidecar(_SID_B, 0, 0.1),
        _sidecar(_SID_A, 2, 0.2),  # gap: session A expected localSeq 1
        _sidecar(_SID_B, 1, 0.3),
    ]
    errs = checks.check_sidecar_events(events)
    assert any(e.startswith("sidecar[2]:") and "localSeq gap" in e for e in errs), errs
    assert not any(e.startswith("sidecar[3]:") for e in errs), errs


def test_sidecar_interleaved_sessions_pass_when_gap_free():
    events = [
        _sidecar(_SID_A, 0, 0.0),
        _sidecar(_SID_B, 0, 0.1),
        _sidecar(_SID_A, 1, 0.2),
        _sidecar(_SID_B, 1, 0.3),
    ]
    assert checks.check_sidecar_events(events) == []


def test_sidecar_session_not_starting_at_zero_reported():
    errs = checks.check_sidecar_events([_sidecar(_SID_A, 3, 0.0)])
    assert any(f"first event of session {_SID_A} has localSeq 3, expected 0" in e for e in errs), errs


# --- Final review B1: check_lock2_text parses strictly ---


def _lock2_with_server_info(info) -> str:
    doc = json.loads(LOCK_TEXT)
    doc["servers"]["fetch"]["envelope"]["entry"]["eras"]["legacy"]["serverInfo"] = info
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def _deep_list(n):
    v = []
    for _ in range(n):
        v = [v]
    return v


@pytest.mark.parametrize("make, needle", [
    (lambda: _lock2_with_server_info({"x": float("nan")}), "strict JSON"),
    (lambda: _lock2_with_server_info({"x": float("inf")}), "strict JSON"),
    (lambda: _lock2_with_server_info({"x": 2**53 + 1}), "2**53"),
    (lambda: _lock2_with_server_info({"x": -(2**53) - 1}), "2**53"),
    (lambda: LOCK_TEXT.replace('"canonicalization":', '"lockScope": "0",\n  "canonicalization":', 1),
     "duplicate key"),
    (lambda: _lock2_with_server_info({"x": _deep_list(200)}), "nesting"),
], ids=["nan", "infinity", "big-int", "negative-big-int", "duplicate-key", "deep-nesting"])
def test_lock2_rejects_non_strict_json(make, needle):
    errs = checks.check_lock2_text(make())
    assert any(needle in e for e in errs), errs


def test_lock2_non_str_or_unencodable_text_returns_errors():
    assert checks.check_lock2_text(LOCK_TEXT[:-2] + "\ud800\n")


# --- Final review C1, C3 ---


@pytest.mark.parametrize("at", ["2026-10-10T18:05:00.5Z", "2026-10-10T18:05:00.12345Z",
                                "2026-10-10T18:05:00.123456789Z"])
def test_attestation_fractional_seconds_of_any_length(at):
    lines = [dict(l) for l in ATTEST]
    lines[1]["at"] = at
    assert checks.check_attestation(lines) == []


def test_attestation_unparseable_time_is_an_error_not_an_exception(monkeypatch):
    def refuse(s):
        raise ValueError("unparseable")

    monkeypatch.setattr(checks, "_parse_at", refuse)
    errs = checks.check_attestation([dict(l) for l in ATTEST])
    assert any("time" in e for e in errs), errs


def test_checks_uses_the_timeutil_grammar():
    with pytest.raises(ValueError):
        checks._parse_at("2026-10-10 18:05:01Z")


def test_checks_requires_format_checkers():
    from jsonschema import FormatChecker
    with pytest.raises(RuntimeError, match="date-time"):
        checks._require_formats(FormatChecker(formats=["uuid"]))
    with pytest.raises(RuntimeError, match="uuid"):
        checks._require_formats(FormatChecker(formats=["date-time"]))
    checks._require_formats(FormatChecker())


# --- Final review D: C3 2.0.0 freeze fixes ---

ATTEST_TEXT = (C / "proxy/example.attestation.jsonl").read_text()


def _lock2_mut(mutate) -> list[str]:
    d = json.loads(LOCK_TEXT)
    mutate(d)
    return checks.check_lock2_text(json.dumps(d, indent=2, sort_keys=True) + "\n")


def test_lock2_time_must_be_utc_z():
    errs = _lock2_mut(lambda d: d["servers"]["fetch"]["envelope"].update(issuedAt="2026-10-10T18:00:00+00:00"))
    assert any("issuedAt" in e for e in errs), errs


@pytest.mark.parametrize("ptr, ok", [
    ("/_meta/a", True), ("/_meta/a/b", True),
    ("/_meta/a//b", False), ("/_meta//a", False), ("/_meta/a/", False), ("/_meta", False), ("/x/a", False),
])
def test_lock2_ignore_field_pointer_pattern(ptr, ok):
    def mutate(d):
        d["servers"]["fetch"]["envelope"]["entry"]["eras"]["legacy"]["ignoreFields"] = [
            {"pointer": ptr, "reason": "timestamp"}]
    errs = _lock2_mut(mutate)
    assert (errs == []) is ok, errs


def test_attestation_state_line_cannot_say_allowed():
    lines = [dict(l) for l in ATTEST[:-1]]
    lines.append({"kind": "state", "seq": len(lines), "at": "2026-10-10T18:06:00Z", "itemType": "tool",
                  "name": "fetch", "state": "allowed", "cause": "x"})
    assert checks.check_attestation(lines)


@pytest.mark.parametrize("kind", ["server", "verdict"])
@pytest.mark.parametrize("ref, ok", [(None, True), ("a" * 64, True), ("abc", False), ("A" * 64, False)])
def test_attestation_store_ref_is_null_or_sha256(kind, ref, ok):
    lines = [dict(l) for l in ATTEST]
    idx = next(i for i, l in enumerate(lines) if l["kind"] == kind)
    lines[idx]["storeRef"] = ref
    assert (checks.check_attestation(lines) == []) is ok


@pytest.mark.parametrize("verdict, sha, ok", [
    ("uncanonicalizable", None, True),
    ("uncanonicalizable", "a" * 64, True),
    ("changed", None, False),
    ("pinned-match", None, False),
    ("uncanonicalizable", "xyz", False),
])
def test_attestation_verdict_sha_nullable_only_when_uncanonicalizable(verdict, sha, ok):
    lines = [dict(l) for l in ATTEST]
    idx = next(i for i, l in enumerate(lines) if l["kind"] == "verdict")
    lines[idx].update(verdict=verdict, sha256=sha)
    assert (checks.check_attestation(lines) == []) is ok


def test_attestation_example_server_line_precedes_verdicts_and_allows_fetch():
    from cxbom import state
    kinds = [l["kind"] for l in ATTEST]
    assert kinds.index("server") < kinds.index("verdict")
    states = state.compute(ATTEST)
    assert state.lookup(states, "tool", "fetch").state == state.ALLOWED


def test_attestation_example_is_reproducible():
    sys.path.insert(0, str(ROOT / "contracts" / "proxy"))
    import make_example
    assert make_example.build_attestation() == ATTEST_TEXT


# --- Final review D8: check_attestation_text ---


def test_attestation_text_example_passes():
    assert checks.check_attestation_text(ATTEST_TEXT) == []


def test_attestation_text_ignores_trailing_partial_line():
    assert checks.check_attestation_text(ATTEST_TEXT + '{"kind":"diag') == []


def _broken_tail(tail_reason: str) -> str:
    lines = ATTEST_TEXT.splitlines()[:-1]
    end = {"at": "2026-10-10T18:07:00Z", "kind": "end", "reason": tail_reason, "seq": len(lines)}
    return "\n".join(lines) + '\n{"kind":"diag\n' + json.dumps(end, sort_keys=True, separators=(",", ":")) + "\n"


def test_attestation_text_tolerates_one_fragment_before_attestation_io_end():
    assert checks.check_attestation_text(_broken_tail("attestation-io")) == []


def test_attestation_text_refuses_fragment_before_other_end():
    errs = checks.check_attestation_text(_broken_tail("eof"))
    assert any("line 5" in e for e in errs), errs


def test_attestation_text_refuses_fragment_in_the_middle():
    lines = ATTEST_TEXT.splitlines()
    text = "\n".join(lines[:2] + ['{"kind":"diag'] + lines[2:]) + "\n"
    assert checks.check_attestation_text(text)


def test_attestation_text_refuses_a_mid_log_fragment_even_before_an_io_end():
    """The tolerance is positional, and only the final pair earns it.

    The recovery record ends the log: the writer took an I/O error and stopped.
    A fragment followed by an `attestation-io` end with more lines after it is
    a different artifact, either a spliced log or a writer that kept going
    after declaring it had stopped, and the framer refuses it at the fragment
    rather than letting the C3 rules explain it as something else. Nothing else
    pins the position, so relaxing `i == n - 2` to `i <= n - 2` reads as a
    tidy-up.
    """
    lines = ATTEST_TEXT.splitlines()
    io_end = json.dumps({"at": "2026-10-10T18:07:00Z", "kind": "end",
                         "reason": "attestation-io", "seq": 2},
                        sort_keys=True, separators=(",", ":"))
    text = "\n".join(lines[:2] + ['{"kind":"diag', io_end] + lines[2:]) + "\n"
    errs = checks.check_attestation_text(text)
    assert any("line 3" in e for e in errs), errs


def test_attestation_text_refuses_final_garbage_line():
    assert checks.check_attestation_text(ATTEST_TEXT + "garbage\n")


def test_attestation_text_refuses_empty_middle_line():
    lines = ATTEST_TEXT.splitlines()
    text = "\n".join(lines[:2] + [""] + lines[2:]) + "\n"
    errs = checks.check_attestation_text(text)
    assert any("empty line" in e for e in errs), errs


@pytest.mark.parametrize("line", [
    '{"at":"2026-10-10T18:06:00Z","kind":"diagnostic","message":"a","message":"b","seq":4}',
    '{"at":"2026-10-10T18:06:00Z","kind":"diagnostic","message":"a","seq":NaN}',
])
def test_attestation_text_parses_strictly(line):
    lines = ATTEST_TEXT.splitlines()
    text = "\n".join(lines[:-1] + [line]) + "\n"
    assert checks.check_attestation_text(text)


@pytest.mark.parametrize("text", ["", "\n", "\ud800\n", None, b"{}\n", "[]\n", "42\n"])
def test_attestation_text_never_raises(text):
    errs = checks.check_attestation_text(text)
    assert errs and all(isinstance(e, str) for e in errs)


# --- Final review E: C2 1.1.0 freeze fixes ---

SIDECAR_TYPES = ["gate_decision", "launch_refused", "lock_checked", "mcp_message", "tool_listed", "tool_swapped"]
GATE_DATA = {"serverId": "fetch", "tool": "fetch", "decision": "block", "reason": "hash differs"}


def _schema(rel):
    return json.loads((C / rel).read_text())


def _type_blocks(schema) -> dict:
    # A block keyed on "not" (the sidecar's non-launch_refused proxySessionId
    # rule) names no single type and is not one of the per-type data blocks
    # this helper indexes.
    return {b["if"]["properties"]["type"]["const"]: b for b in schema.get("allOf", []) if "properties" in b["if"]}


def test_sidecar_data_blocks_match_the_merged_schema():
    # The five 1.1.0 types compare whole (their block only ever constrains
    # "data"). launch_refused (C2 1.2.0) is compared by its "data"
    # sub-schema only: the sidecar's block also constrains proxySessionId
    # and localSeq for its null-session line, which the merged event has no
    # equivalent of.
    sidecar, merged = _schema("events/sidecar-event.schema.json"), _schema("events/event.schema.json")
    side_blocks, merged_blocks = _type_blocks(sidecar), _type_blocks(merged)
    assert sorted(side_blocks) == sorted(sidecar["properties"]["type"]["enum"]) == SIDECAR_TYPES
    for t in SIDECAR_TYPES:
        if t == "launch_refused":
            assert side_blocks[t]["then"]["properties"]["data"] == merged_blocks[t]["then"]["properties"]["data"], t
        else:
            assert side_blocks[t] == merged_blocks[t], t
    assert sidecar["$defs"]["sha256"] == merged["$defs"]["sha256"]


@pytest.mark.parametrize("typ, data", [
    ("tool_listed", {}),
    ("gate_decision", dict(GATE_DATA, extra=1)),
    ("lock_checked", {"serverId": "fetch", "tool": "fetch", "expectedSha256": None,
                      "actualSha256": "short", "match": False}),
    ("mcp_message", {"from": "agent", "to": "nobody", "method": "x", "rpcId": 1, "summary": "s"}),
    ("tool_swapped", {"serverId": "fetch", "tool": "fetch"}),
])
def test_sidecar_data_is_constrained_per_type(typ, data):
    ev = dict(_sidecar(_SID_A, 0, 0.0), type=typ, data=data)
    assert checks.check_sidecar_events([ev])


@pytest.mark.parametrize("decision, ok", [("allow", True), ("block", True), ("would-block", True),
                                          ("maybe", False)])
def test_gate_decision_enum_in_the_sidecar_schema(decision, ok):
    # A sidecar line carries no run_started, so the gate/decision pairing cannot
    # apply here. This pins only the enum: the sidecar schema admits all three
    # decisions and refuses an unknown one. The merged-stream pairing, which
    # does read the run's gate, is pinned by the C2 pairing tests below.
    side = dict(_sidecar(_SID_A, 0, 0.0), data=dict(GATE_DATA, decision=decision))
    assert (checks.check_sidecar_events([side]) == []) is ok


def test_gate_decision_enum_refused_in_the_merged_schema():
    # The merged event schema carries the same enum. An unknown value is a
    # schema error, distinct from a schema-valid decision that mispairs with the
    # gate (that is the pairing rule, pinned below).
    ev = copy.deepcopy(EVENTS)
    idx = next(i for i, e in enumerate(ev) if e["type"] == "gate_decision")
    ev[idx]["data"]["decision"] = "maybe"
    assert checks.check_events(ev)


# --- C2 gate/decision/outcome pairing (the Jetson's C2 request) ---
#
# The contract binds gate_decision.decision and run_finished.outcome to the
# run's run_started.gate, which the JSON Schema cannot express across events:
#   off      no gate_decision at all: off runs no lockfile checks and no proxy,
#            and gate_decision is a proxy event (README C2; lab-j2 S2a).
#   observe  allow or would-block: observe logs the block enforce would make,
#            then forwards, so it never blocks (README C2: would-block "only in
#            a run whose run_started.gate is observe").
#   enforce  allow or block: enforce blocks a mismatch and never would-blocks.
# Outcome reads against the gate too: "blocked" is reachable only under enforce
# (README C2: a benign-update and a rug-pull "both end blocked under
# gate: enforce"); observe and off end exfiltrated, no-attack, or aborted.

def _c2_stream(gate, decision, outcome):
    """A minimal well-formed C2 stream with one settable gate, gate_decision,
    and outcome, so each pairing rule is exercised by exactly one field.

    check_events does not verify the prev_sha256 chain bytes (check_events_text
    does), so a constant 64-hex placeholder is a valid non-null prev at seq > 0.
    """
    sha = "0" * 64

    def env(seq, t, typ, data, prev):
        return {"v": 1, "seq": seq, "t": float(t), "run": "c2-pairing",
                "type": typ, "data": data, "prev_sha256": prev}

    evs = [env(0, 0.0, "run_started",
               {"scenario": "rug-pull", "gate": gate, "model": {"id": "m", "revision": "r"},
                "synthetic": True, "demonstration": True}, None)]
    seq = 1
    if decision is not None:
        evs.append(env(seq, 1.0, "gate_decision",
                       {"serverId": "notes", "tool": "search_notes", "decision": decision,
                        "reason": "changed"}, sha))
        seq += 1
    evs.append(env(seq, 2.0, "run_finished", {"outcome": outcome}, sha))
    return evs


def test_c2_pairing_builder_is_well_formed():
    # Positive control: without this, a rejection below could be a malformed
    # fixture rather than the pairing rule firing.
    assert checks.check_events(_c2_stream("enforce", "block", "blocked")) == []


@pytest.mark.parametrize("gate, decision, outcome", [
    ("enforce", "block", "blocked"),
    ("enforce", "allow", "exfiltrated"),
    ("observe", "would-block", "exfiltrated"),
    ("observe", "allow", "no-attack"),
    ("off", None, "exfiltrated"),
    ("off", None, "aborted"),
])
def test_c2_valid_gate_decision_outcome_pairs_pass(gate, decision, outcome):
    assert checks.check_events(_c2_stream(gate, decision, outcome)) == []


@pytest.mark.parametrize("gate, decision, needle", [
    # The outcome stays exfiltrated, which every gate can produce, so only the
    # decision rule fires: one input hitting two guards would pin neither.
    ("enforce", "would-block", "does not pair with gate 'enforce'"),   # the Jetson's case 1
    ("observe", "block", "does not pair with gate 'observe'"),         # sibling of case 1
    ("off", "block", "gate_decision under gate 'off' is impossible"),  # the Jetson's case 2
    ("off", "allow", "gate_decision under gate 'off' is impossible"),  # sibling of case 2
    ("off", "would-block", "gate_decision under gate 'off' is impossible"),  # sibling
])
def test_c2_mismatched_decision_is_rejected(gate, decision, needle):
    errs = checks.check_events(_c2_stream(gate, decision, "exfiltrated"))
    assert any(needle in e for e in errs), errs


@pytest.mark.parametrize("gate, decision", [("observe", "allow"), ("off", None)])
def test_c2_blocked_outcome_requires_enforce(gate, decision):
    # The decision is one the gate accepts, so only the outcome rule fires.
    errs = checks.check_events(_c2_stream(gate, decision, "blocked"))
    assert any("outcome 'blocked' requires gate 'enforce'" in e for e in errs), errs


@pytest.mark.parametrize("outcome", ["exfiltrated", "no-attack", "aborted"])
def test_c2_non_blocked_outcomes_pass_under_off_and_observe(outcome):
    # The outcome rule must reject only "blocked", not every non-enforce outcome.
    assert checks.check_events(_c2_stream("off", None, outcome)) == []
    assert checks.check_events(_c2_stream("observe", "allow", outcome)) == []


@pytest.mark.parametrize("old, new", [
    ('"t":10.5,', '"t":NaN,'),
    ('"t":10.5,', '"t":Infinity,'),
    ('"t":10.5,', '"t":10.5,"t":10.5,'),
])
def test_events_text_parses_strictly(old, new):
    text = (C / "events/example-rug-pull-gate-on.events.jsonl").read_text()
    lines = text[:-1].split("\n")
    assert old in lines[-1]
    lines[-1] = lines[-1].replace(old, new)
    errs = checks.check_events_text("\n".join(lines) + "\n")
    assert any(f"event[{len(lines) - 1}]" in e for e in errs), errs


# --- Task 14b: C2 1.2.0, launch_refused, launch-pin scenario ---

LAUNCH_REFUSED_DATA = {"serverId": "fetch", "item": "argv", "reason": "the server command differs", "exitCode": 2}


def _launch_refused(mono=0.0) -> dict:
    return {"v": 1, "at": "2026-10-10T18:00:00Z", "mono": mono, "proxySessionId": None, "localSeq": 0,
            "type": "launch_refused", "data": dict(LAUNCH_REFUSED_DATA)}


def test_launch_refused_sidecar_example_validates():
    assert checks.check_sidecar_events([_launch_refused()]) == []


def test_launch_refused_then_a_normal_session_passes():
    # Fix round 1, ruling: S4 restarts the proxy against the same --events
    # path after a refusal, so a launch_refused line followed by a real
    # session's lines is not an error.
    lines = [_launch_refused(), _sidecar(_SID_A, 0, 0.1), _sidecar(_SID_A, 1, 0.2)]
    assert checks.check_sidecar_events(lines) == []


def test_two_launch_refused_lines_then_a_session_passes():
    lines = [_launch_refused(mono=0.0), _launch_refused(mono=0.1), _sidecar(_SID_A, 0, 0.2)]
    assert checks.check_sidecar_events(lines) == []


def test_launch_refused_lines_interleaved_with_a_session_pass():
    # "Anywhere" means anywhere, not only before every session line.
    lines = [_sidecar(_SID_A, 0, 0.0), _launch_refused(mono=0.1), _sidecar(_SID_A, 1, 0.2),
             _launch_refused(mono=0.3)]
    assert checks.check_sidecar_events(lines) == []


def test_launch_refused_rejects_a_real_session_id():
    ev = dict(_launch_refused(), proxySessionId=_SID_A)
    assert checks.check_sidecar_events([ev])


def test_launch_refused_rejects_nonzero_local_seq():
    ev = dict(_launch_refused(), localSeq=1)
    assert checks.check_sidecar_events([ev])


def test_launch_refused_unknown_item_fails():
    ev = dict(_launch_refused(), data=dict(LAUNCH_REFUSED_DATA, item="binaries"))
    assert checks.check_sidecar_events([ev])


def test_launch_refused_exit_code_must_be_2():
    ev = dict(_launch_refused(), data=dict(LAUNCH_REFUSED_DATA, exitCode=1))
    assert checks.check_sidecar_events([ev])


def test_launch_refused_reason_over_512_chars_fails():
    ev = dict(_launch_refused(), data=dict(LAUNCH_REFUSED_DATA, reason="x" * 513))
    assert checks.check_sidecar_events([ev])


def test_launch_refused_in_the_merged_stream_validates():
    ev = copy.deepcopy(EVENTS)
    frame = {"v": 1, "t": ev[0]["t"], "run": ev[0]["run"], "type": "launch_refused",
             "data": dict(LAUNCH_REFUSED_DATA), "prev_sha256": "a" * 64}
    ev.insert(1, frame)
    for i, e in enumerate(ev):
        e["seq"] = i
    assert checks.check_events(ev) == []


def test_run_started_scenario_launch_pin_validates():
    ev = copy.deepcopy(EVENTS)
    ev[0]["data"]["scenario"] = "launch-pin"
    assert checks.check_events(ev) == []


def test_run_started_scenario_rejects_unknown_value():
    ev = copy.deepcopy(EVENTS)
    ev[0]["data"]["scenario"] = "launch-refusal"
    assert checks.check_events(ev)


def test_existing_1_1_0_example_still_validates_under_1_2_0():
    # The schema bump to 1.2.0 is additive: the rug-pull example recorded
    # under 1.1.0 carries no launch_refused line and must still pass whole.
    assert checks.check_events(EVENTS) == []
    assert checks.check_events_text((C / "events/example-rug-pull-gate-on.events.jsonl").read_text()) == []


# --- Task 7: C2 1.3.0, aborted, and the terminal and attestation panes ---

def c2_stream(*events) -> str:
    """Serialize a merged stream, chaining prev_sha256 while writing."""
    lines, prev = [], None
    for i, (etype, data) in enumerate(events):
        obj = {"v": 1, "seq": i, "t": float(i), "run": "demo-c2-130", "type": etype,
               "data": data, "prev_sha256": prev}
        line = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        lines.append(line)
        prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
    return "\n".join(lines) + "\n"


STARTED = ("run_started", {"scenario": "rug-pull", "gate": "enforce",
                           "model": {"id": "Qwen3-8B", "revision": "b" * 40},
                           "synthetic": False, "demonstration": True})


def test_aborted_is_a_run_finished_outcome():
    assert checks.check_events_text(c2_stream(STARTED, ("run_finished", {"outcome": "aborted"}))) == []


def test_an_unknown_outcome_still_fails():
    errs = checks.check_events_text(c2_stream(STARTED, ("run_finished", {"outcome": "fine"})))
    assert errs and "outcome" in errs[0]


@pytest.mark.parametrize("scenario", ["benign-update", "malicious-at-approval"])
def test_the_honest_pair_of_scenarios_validates_under_enforce(scenario):
    """Both new scenarios run with the gate on, and neither needs a new field.

    benign-update is a legitimate version bump whose tool description changed,
    so the gate blocks it and the take shows the false-positive cost.
    malicious-at-approval was already malicious when it was approved, so the pin
    holds and the gate never fires, which is the limit of pinning. Neither
    couples gate to outcome, so the only contract change is the enum.
    """
    started = ("run_started", dict(STARTED[1], scenario=scenario, gate="enforce"))
    for outcome in ("blocked", "exfiltrated"):
        assert checks.check_events_text(
            c2_stream(started, ("run_finished", {"outcome": outcome}))) == []


def test_an_unknown_scenario_still_fails():
    errs = checks.check_events_text(c2_stream(
        ("run_started", dict(STARTED[1], scenario="benign_update")),
        ("run_finished", {"outcome": "blocked"})))
    assert errs and "scenario" in errs[0], errs


# One valid instance of each new event's data, so a negative below differs
# from a pass by exactly the constraint it is aimed at.
_STDERR_OK = {"serverId": "notes", "text": "proxy notes: session open, mode enforce"}
_EXITED_OK = {"serverId": "notes", "exitCode": 0}
_APPENDED_OK = {"serverId": "notes", "kind": "server", "seq": 1, "sha256": "a" * 64,
                "summary": "server pinned-match"}


def _without(data: dict, key: str) -> dict:
    return {k: v for k, v in data.items() if k != key}


def _one_event_errs(etype: str, data: dict) -> list[str]:
    """Run one new event through a minimal well-formed stream."""
    return checks.check_events_text(c2_stream(STARTED, (etype, data),
                                              ("run_finished", {"outcome": "blocked"})))


def test_the_terminal_pane_events_validate():
    text = c2_stream(STARTED, ("proxy_stderr", _STDERR_OK), ("proxy_exited", _EXITED_OK),
                     ("run_finished", {"outcome": "blocked"}))
    assert checks.check_events_text(text) == []


# Each case names the error it must produce. A bare "errs is non-empty" would
# pass on the wrong error, so a constraint could be deleted while some other
# rule kept the test green: exitCode 0 with the required list gone, say, still
# trips the integer guard.
@pytest.mark.parametrize("data,expect", [
    (dict(_EXITED_OK, exitCode=-1), "data/exitCode"),
    (dict(_EXITED_OK, exitCode=300), "data/exitCode"),
    (_without(_EXITED_OK, "exitCode"), "'exitCode' is a required property"),
    (_without(_EXITED_OK, "serverId"), "'serverId' is a required property"),
    (dict(_EXITED_OK, extra=1), "Additional properties are not allowed"),
    (dict(_EXITED_OK, serverId="../notes"), "data/serverId"),
])
def test_a_bad_proxy_exited_fails(data, expect):
    errs = _one_event_errs("proxy_exited", data)
    assert any(expect in e for e in errs), errs


@pytest.mark.parametrize("data,expect", [
    (_without(_STDERR_OK, "text"), "'text' is a required property"),
    (_without(_STDERR_OK, "serverId"), "'serverId' is a required property"),
    (dict(_STDERR_OK, text="x" * 201), "data/text"),
    (dict(_STDERR_OK, serverId="../notes"), "data/serverId"),
    (dict(_STDERR_OK, extra=1), "Additional properties are not allowed"),
])
def test_a_bad_proxy_stderr_fails(data, expect):
    errs = _one_event_errs("proxy_stderr", data)
    assert any(expect in e for e in errs), errs


@pytest.mark.parametrize("data,expect", [
    (_without(_APPENDED_OK, "serverId"), "'serverId' is a required property"),
    (_without(_APPENDED_OK, "kind"), "'kind' is a required property"),
    (_without(_APPENDED_OK, "seq"), "'seq' is a required property"),
    (_without(_APPENDED_OK, "sha256"), "'sha256' is a required property"),
    (_without(_APPENDED_OK, "summary"), "'summary' is a required property"),
    (dict(_APPENDED_OK, extra=1), "Additional properties are not allowed"),
    (dict(_APPENDED_OK, kind="banana"), "data/kind"),
    (dict(_APPENDED_OK, seq=0), "data/seq"),
    (dict(_APPENDED_OK, summary="x" * 201), "data/summary"),
    (dict(_APPENDED_OK, serverId="../notes"), "data/serverId"),
    (dict(_APPENDED_OK, sha256="beef"), "data/sha256"),
    (dict(_APPENDED_OK, sha256="A" * 64), "data/sha256"),
])
def test_a_bad_attestation_appended_fails(data, expect):
    errs = _one_event_errs("attestation_appended", data)
    assert any(expect in e for e in errs), errs


# JSON Schema's "integer" accepts a zero-fraction float, so the schema alone
# lets 1.0 and 0.0 through. C3's check_attestation refuses a float seq
# outright, and C2 says it in the same words.

def test_a_float_attestation_seq_is_refused():
    errs = _one_event_errs("attestation_appended", dict(_APPENDED_OK, seq=1.0))
    assert any("seq must be an integer, not a float or bool" in e for e in errs), errs


def test_a_float_exit_code_is_refused():
    errs = _one_event_errs("proxy_exited", dict(_EXITED_OK, exitCode=0.0))
    assert any("exitCode must be an integer, not a float or bool" in e for e in errs), errs


def _appended(**over) -> tuple:
    """One attestation_appended event, valid unless an override says otherwise."""
    return ("attestation_appended", dict(_APPENDED_OK, **over))


def _session(n: int, **over) -> tuple:
    """A session line event carrying a hash of its own.

    C3 mints a fresh proxySessionId per writer and records startedAt and pid,
    so no two genuine session lines share their bytes. check_events says so, and
    a fixture holding two session lines for one server needs two hashes.
    """
    return _appended(kind="session", seq=None, sha256=f"{n:064x}", **over)


def test_the_attestation_pane_events_validate_and_order_per_server():
    # The two session lines share a sha256, which is legal because they name
    # different servers and the distinctness rule is scoped per serverId. Two
    # real session lines for two servers differ anyway: serverId is in the bytes.
    text = c2_stream(STARTED,
                     _appended(kind="session", seq=None, summary="session mode enforce"),
                     _appended(serverId="fetch", kind="session", seq=None,
                               summary="session mode enforce"),
                     _appended(kind="server", seq=1, summary="server pinned-match"),
                     _appended(kind="verdict", seq=2, summary="verdict search_notes changed"),
                     ("run_finished", {"outcome": "blocked"}))
    assert checks.check_events_text(text) == []


def test_a_session_line_with_a_sequence_is_refused():
    errs = _one_event_errs("attestation_appended", dict(_APPENDED_OK, kind="session", seq=1))
    assert any("session" in e for e in errs), errs


def test_a_non_session_line_without_a_sequence_is_refused():
    errs = _one_event_errs("attestation_appended", dict(_APPENDED_OK, kind="server", seq=None))
    assert any("session" in e for e in errs), errs


def test_an_attestation_sequence_gap_is_refused():
    errs = checks.check_events_text(c2_stream(
        STARTED, _appended(kind="server", seq=1), _appended(kind="verdict", seq=3),
        ("run_finished", {"outcome": "blocked"})))
    assert any("contiguous" in e for e in errs), errs


def test_an_attestation_sequence_must_start_at_one():
    errs = _one_event_errs("attestation_appended", dict(_APPENDED_OK, kind="server", seq=2))
    assert any("contiguous" in e for e in errs), errs


def test_two_servers_keep_their_own_attestation_sequences():
    text = c2_stream(
        STARTED, _appended(serverId="notes", kind="server", seq=1),
        _appended(serverId="fetch", kind="server", seq=1),
        ("run_finished", {"outcome": "no-attack"}))
    assert checks.check_events_text(text) == []


def test_a_proxy_restart_starts_one_server_s_attestation_sequence_over():
    """C3 writes one log per proxy session, so a restart is a second log, not a gap.

    No J2 take records two logs for one server, and the rule is contract
    generality rather than a take: C3 names a log
    `<serverId>-<proxySessionId>.jsonl`, so a second session for one server is a
    second file whose seq starts at 1, and keyed on serverId alone the merged
    stream refused that pair of valid logs. S4 is the only take that launches a
    proxy twice and it is not this shape: its refused launch writes no log at
    all (spec 4.3 S4, "No `session` line is written" and "no attestation file
    created"), so it records one log for `fetch`. check_sidecar_events already
    tracks localSeq per proxySessionId, so the two layers agree.
    """
    text = c2_stream(STARTED,
                     _session(1, summary="session one"),
                     _appended(kind="server", seq=1),
                     _appended(kind="end", seq=2, summary="end attestation-io"),
                     _session(2, summary="session two"),
                     _appended(kind="server", seq=1),
                     _appended(kind="verdict", seq=2),
                     ("run_finished", {"outcome": "blocked"}))
    assert checks.check_events_text(text) == []


def test_a_gap_inside_one_attestation_log_still_fails_after_a_restart():
    """The restart is the only thing relaxed. Within a log, contiguity is unchanged."""
    text = c2_stream(STARTED,
                     _session(1, summary="session one"),
                     _appended(kind="server", seq=1),
                     _session(2, summary="session two"),
                     _appended(kind="server", seq=1),
                     _appended(kind="verdict", seq=3),
                     ("run_finished", {"outcome": "blocked"}))
    errs = checks.check_events_text(text)
    assert any("attestation seq 3 for notes is not contiguous (expected 2)" in e
               for e in errs), errs


def test_a_restart_of_one_server_does_not_reset_another_server():
    """The reset is per server as well as per log, or one restart hides another's gap."""
    text = c2_stream(STARTED,
                     _session(1, serverId="notes", summary="s"),
                     _appended(serverId="notes", kind="server", seq=1),
                     _session(2, serverId="fetch", summary="s"),
                     _appended(serverId="fetch", kind="server", seq=1),
                     _session(3, serverId="notes", summary="s"),
                     _appended(serverId="fetch", kind="verdict", seq=3),
                     ("run_finished", {"outcome": "blocked"}))
    errs = checks.check_events_text(text)
    assert any("attestation seq 3 for fetch is not contiguous (expected 2)" in e
               for e in errs), errs


def test_a_second_session_line_repeating_the_first_s_hash_is_refused():
    """The stream carries one log twice, which the restart allowance would accept.

    Every other rule passes it: the seq restart is legal, so contiguity is
    satisfied, and attestation_appended holds the C3 line's hash and not its
    payload, so nothing else in the event distinguishes the two session lines.
    A genuine session line carries a fresh proxySessionId, so the hash is the
    session identity the stream already has.
    """
    text = c2_stream(STARTED,
                     _session(1, summary="session one"),
                     _appended(kind="server", seq=1),
                     _session(1, summary="session one"),
                     _appended(kind="server", seq=1),
                     ("run_finished", {"outcome": "blocked"}))
    errs = checks.check_events_text(text)
    assert any("the session line for notes repeats an earlier session line's sha256" in e
               for e in errs), errs


def test_two_servers_may_repeat_each_other_s_session_hash():
    """The rule is per serverId, which is the scope the restart rule uses.

    A real pair here differs anyway, since serverId is in the attested bytes.
    Asserted so a widening of the rule to the whole stream reports as a
    deliberate change rather than as this fixture going red for no stated reason.
    """
    text = c2_stream(STARTED,
                     _session(1, serverId="notes", summary="s"),
                     _session(1, serverId="fetch", summary="s"),
                     ("run_finished", {"outcome": "blocked"}))
    assert checks.check_events_text(text) == []


def test_the_sidecar_schema_gains_no_type():
    sidecar = json.loads((C / "events" / "sidecar-event.schema.json").read_text(encoding="utf-8"))
    merged = json.loads((C / "events" / "event.schema.json").read_text(encoding="utf-8"))
    assert "1.4.0" in sidecar["$id"] and "1.4.0" in merged["$id"]
    new = {"attestation_appended", "proxy_exited", "proxy_stderr"}
    assert new <= set(merged["properties"]["type"]["enum"])
    assert not (new & set(sidecar["properties"]["type"]["enum"])), "these three are demo-written"


# The two sources the dashboard's attestation pane can read. A recorded take
# replays the run bundle's C3 log, a live take follows the C2 events, and the
# controller's ruling is that both must carry the same lines.

SERVER = ATTEST[0]["serverId"]


def _line_sha256(raw: str) -> str:
    """The hash attestation_appended.sha256 carries: the line's bytes, no newline."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _pane_events_from_log_text(text: str, server: str) -> list[tuple]:
    """Derive the attestation_appended events a live take writes from one C3 log.

    Built from the log's text, not its parsed lines, because the harness hashes
    the bytes it read. A re-serialization is not the same artifact: the writer
    encodes with ensure_ascii=False and json.dumps does not by default.
    """
    out = []
    for raw in text.splitlines():
        ln = json.loads(raw)
        out.append(("attestation_appended",
                    {"serverId": server, "kind": ln["kind"], "seq": ln.get("seq"),
                     "sha256": _line_sha256(raw),
                     "summary": f"{ln['kind']} {ln.get('verdict') or ln.get('reason') or ''}".strip()}))
    return out


def _c3_text(lines: list[dict]) -> str:
    """Serialize C3 lines the way cxbom.attestation writes them."""
    return "".join(json.dumps(ln, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
                   for ln in lines)


def _parse(text: str) -> list[dict]:
    return [json.loads(ln) for ln in text.splitlines()]


def _pane_stream(log_text: str, server: str = SERVER, outcome: str = "blocked",
                 drop_last: bool = False) -> str:
    pane = _pane_events_from_log_text(log_text, server)
    if drop_last:
        pane = pane[:-1]
    return c2_stream(STARTED, *pane, ("run_finished", {"outcome": outcome}))


def test_the_two_attestation_sources_agree_on_the_committed_log():
    text = _pane_stream(ATTEST_TEXT)
    assert checks.check_events_text(text) == []
    assert checks.check_attestation_text(ATTEST_TEXT) == []
    assert checks.check_attestation_agreement(ATTEST_TEXT, _parse(text)) == []


def test_a_pane_missing_a_log_line_is_refused():
    # Drop the log's last line (end), which leaves the remaining sequence
    # contiguous, so only the agreement check can catch the loss.
    text = _pane_stream(ATTEST_TEXT, drop_last=True)
    assert checks.check_events_text(text) == []
    errs = checks.check_attestation_agreement(ATTEST_TEXT, _parse(text))
    assert any("has 5 lines and the stream has 4" in e for e in errs), errs


def test_a_pane_that_renames_a_log_line_is_refused():
    pane = _pane_events_from_log_text(ATTEST_TEXT, SERVER)
    pane[1] = ("attestation_appended", dict(pane[1][1], kind="diagnostic"))
    text = c2_stream(STARTED, *pane, ("run_finished", {"outcome": "blocked"}))
    assert checks.check_events_text(text) == []
    errs = checks.check_attestation_agreement(ATTEST_TEXT, _parse(text))
    sha = _line_sha256(ATTEST_TEXT.splitlines()[1])
    assert any(f"protocol/1/{sha} in the log and diagnostic/1/{sha} in the stream" in e
               for e in errs), errs


def test_a_pane_for_another_server_does_not_count_as_agreement():
    text = _pane_stream(ATTEST_TEXT, server="notes")
    assert checks.check_events_text(text) == []
    errs = checks.check_attestation_agreement(ATTEST_TEXT, _parse(text))
    assert any("has 5 lines and the stream has 0" in e for e in errs), errs


def _second_take_of_the_same_server() -> str:
    """A second, valid C3 log for the same server as the committed one.

    Same kinds in the same order and the same sequence numbers, because a C3
    kind sequence is stereotyped: session, protocol, server, verdict, end. What
    differs is everything that identifies the take, and the verdict line names
    a different tool with a different hash. This is the common case, not a
    corner: two takes of one demo server look exactly like this.
    """
    lines = [json.loads(ln) for ln in ATTEST_TEXT.splitlines()]
    lines[0] = dict(lines[0], proxySessionId="9f1e6a2c-0b4d-4f6a-8c3e-1d5b7a9f0c22",
                    envelopeSha256="c" * 64, launchSha256="d" * 64)
    lines[3] = dict(lines[3], name="exfiltrate_everything", sha256="e" * 64, verdict="changed")
    return _c3_text(lines)


def test_a_pane_from_a_different_take_of_the_same_server_is_refused():
    """Kind and sequence identify a position in the sequence, not a line.

    Both takes are valid logs and the stream is well formed, so nothing but
    the per-line hash separates them. Before attestation_appended carried
    sha256, this pair certified as agreeing, which let the demo's central
    on-camera claim ("the two panes agree") hold across two different
    sessions.
    """
    take_b = _second_take_of_the_same_server()
    assert checks.check_attestation_text(take_b) == []
    text = _pane_stream(take_b, outcome="exfiltrated")
    assert checks.check_events_text(text) == []
    # The pair the old comparison looked at is identical on both sides.
    pane = _pane_events_from_log_text(take_b, SERVER)
    assert [(ln["kind"], ln.get("seq")) for ln in ATTEST] == [(d["kind"], d["seq"])
                                                              for _, d in pane]
    errs = checks.check_attestation_agreement(ATTEST_TEXT, _parse(text))
    assert errs and all("in the log and" in e for e in errs), errs


def test_a_restart_whose_session_line_differs_only_by_its_uuid_is_accepted():
    """The narrowest genuine restart, and the reason the rule stops at the session line.

    Same proxy, same server, a relaunch inside the same second: only
    proxySessionId differs, so every later line of the second log is byte for
    byte the first log's, asserted below. A distinctness rule over all of a
    server's lines would refuse this pair of valid logs, which is why it covers
    session lines only.
    """
    lines = [json.loads(ln) for ln in ATTEST_TEXT.splitlines()]
    again = _c3_text([dict(lines[0], proxySessionId="9f1e6a2c-0b4d-4f6a-8c3e-1d5b7a9f0c22")]
                     + lines[1:])
    assert checks.check_attestation_text(again) == []
    first, second = ATTEST_TEXT.splitlines(), again.splitlines()
    assert _line_sha256(first[0]) != _line_sha256(second[0]), "the uuid is in the session line"
    assert [_line_sha256(ln) for ln in first[1:]] == [_line_sha256(ln) for ln in second[1:]], (
        "every later line of the two logs is byte-identical")
    pane = (_pane_events_from_log_text(ATTEST_TEXT, SERVER)
            + _pane_events_from_log_text(again, SERVER))
    text = c2_stream(STARTED, *pane, ("run_finished", {"outcome": "blocked"}))
    assert checks.check_events_text(text) == []


def test_a_pane_that_keeps_a_stale_hash_for_a_line_is_refused():
    """The narrow form: one line's bytes changed and the pane's hash did not."""
    lines = [json.loads(ln) for ln in ATTEST_TEXT.splitlines()]
    lines[4] = dict(lines[4], reason="attestation-io")
    take_b = _c3_text(lines)
    assert checks.check_attestation_text(take_b) == []
    text = _pane_stream(ATTEST_TEXT)  # the pane still describes the committed log
    errs = checks.check_attestation_agreement(take_b, _parse(text))
    assert any("line 4 of " in e for e in errs), errs


def _framed_lines_only(text: str) -> str:
    """Drop a short-write fragment from a log's text, leaving the lines that framed.

    The contract's rule, written out rather than borrowed from
    _frame_attestation: a tolerated fragment was never a complete line, so the
    pane carries no event for it. Deriving the fixture from the function under
    test would make the test agree with whatever that function does.
    """
    kept = []
    for raw in text.splitlines():
        try:
            json.loads(raw)
        except json.JSONDecodeError:
            continue
        kept.append(raw)
    return "".join(raw + "\n" for raw in kept)


def test_the_two_sources_agree_on_a_log_that_recovered_from_a_short_write():
    """The alignment invariant inside _frame_attestation, on the shape that reaches the demo.

    The framer keeps two lists in step: the bytes of each line that parsed and
    the objects they parsed to. A tolerated fragment must land in neither, or
    every later line of the log is compared against the bytes of the line
    before it. Nothing else here exercises the agreement check on a log
    carrying a recovery record, and that is the one shape a real short write
    produces, so an off-by-one there surfaces as the attestation pane
    disagreeing with itself on camera.
    """
    log = _broken_tail("attestation-io")
    assert checks.check_attestation_text(log) == []
    assert len(_framed_lines_only(log).splitlines()) == 5, "4 kept lines plus the recovery end"
    text = _pane_stream(_framed_lines_only(log), outcome="aborted")
    assert checks.check_events_text(text) == []
    assert checks.check_attestation_agreement(log, _parse(text)) == []


def test_the_agreement_check_refuses_a_stream_covering_two_proxy_sessions():
    """A stream carrying two logs for one server, and this check takes one.

    Without this the caller gets a line-count difference, which reads as the two
    panes disagreeing rather than as the stream needing a slice per log. Each
    slice agrees with its own log, which the second half asserts, so the message
    is about how the check was called and not about the artifacts.

    Two different logs, not one log twice. One log twice is a separate error
    that check_events reports, and building this fixture from it would make the
    message depend on which of the two rules fired first.
    """
    take_b = _second_take_of_the_same_server()
    pane_a = _pane_events_from_log_text(ATTEST_TEXT, SERVER)
    pane_b = _pane_events_from_log_text(take_b, SERVER)
    text = c2_stream(STARTED, *pane_a, *pane_b, ("run_finished", {"outcome": "exfiltrated"}))
    assert checks.check_events_text(text) == [], "a restart is a valid stream"
    errs = checks.check_attestation_agreement(ATTEST_TEXT, _parse(text))
    assert any(f"2 attestation logs for {SERVER}" in e for e in errs), errs
    one_a = c2_stream(STARTED, *pane_a, ("run_finished", {"outcome": "blocked"}))
    one_b = c2_stream(STARTED, *pane_b, ("run_finished", {"outcome": "exfiltrated"}))
    assert checks.check_attestation_agreement(ATTEST_TEXT, _parse(one_a)) == []
    assert checks.check_attestation_agreement(take_b, _parse(one_b)) == []


def test_a_log_appended_to_the_stream_twice_is_caught_on_the_merged_stream():
    """Where the duplicate-log rule bites, and the one place it cannot.

    A slice holds one session line, so nothing inside it separates a duplicated
    log from the genuine restart it imitates: the slice is a valid pane for a
    valid log. The merged stream is where the two session lines meet, so the
    call that catches this is check_events_text over the whole stream. Only
    S1's acceptance block in spec section 4.3 names that call, which is why
    spec section 8 requires it of every take in the same breath as the per-log
    cadence: the cadence on its own is the call pattern that hides a duplicated
    log. check_attestation_agreement runs check_events too, so it reports this
    as well when handed the whole stream. Asserted together so the per-log
    cadence is not read as the only place the stream is checked.
    """
    pane = _pane_events_from_log_text(ATTEST_TEXT, SERVER)
    text = c2_stream(STARTED, *pane, *pane, ("run_finished", {"outcome": "blocked"}))
    needle = f"the session line for {SERVER} repeats an earlier session line's sha256"
    assert any(needle in e for e in checks.check_events_text(text))
    assert any(needle in e for e in checks.check_attestation_agreement(ATTEST_TEXT, _parse(text)))
    one = c2_stream(STARTED, *pane, ("run_finished", {"outcome": "blocked"}))
    assert checks.check_attestation_agreement(ATTEST_TEXT, _parse(one)) == [], (
        "a slice of one log cannot see the duplication, which is why the "
        "merged-stream call carries this rule")


def test_the_readme_says_attestation_contiguity_is_per_log_not_per_server():
    """The rule changed under two readers, so both places say so.

    A harness author who reads only the type-table paragraph or only the
    version-history entry has to learn the same thing, and a section-wide
    search would let either go stale behind the other.
    """
    prose = _flat(_c2_paragraph("`attestation_appended.seq` follows C3 2.0.0's rule"))
    assert "every later line of the same log is contiguous from 1" in prose
    assert "tracks the sequence per log" in prose
    assert "restarts a proxy against one server starts that server's count over" in prose
    assert "checks.check_sidecar_events" in prose and "proxySessionId" in prose
    assert "Contiguity stays strict inside one log" in prose

    entry = _flat(_c2_bullet("- `checks.check_events` requires an `attestation_appended`"))
    # Both halves of the entry, or it can say "same server" in the rule and
    # "per log" in the gloss and contradict itself while staying green.
    assert "every later line of the same log to be contiguous" in entry
    assert "Per log and not per server" in entry
    assert "restarts a proxy against one server" in entry
    assert "checks.check_sidecar_events" in entry
    assert "A gap inside one log is still an error" in entry


def test_the_readme_says_two_session_lines_for_one_server_must_differ():
    """The condition on the restart allowance, pinned at both of its sites.

    Same argument as the test above, and the same failure it was written for: one
    guard covering the paragraph and the entry together lets a single-site edit
    through. The paragraph is what a harness author reads and the entry is what a
    consumer upgrading from 1.2.0 reads.
    """
    prose = _flat(_c2_paragraph("Two session lines for one server must carry different"))
    assert "`checks.check_events` requires it" in prose
    assert "fresh `proxySessionId` per writer" in prose
    assert "one log written into the stream twice rather than a restart" in prose
    assert "covers session lines only" in prose
    assert "byte-identical `protocol` and `server` lines" in prose

    entry = _flat(_c2_bullet("- `checks.check_events` also requires two"))
    assert "session lines for one server to carry different `sha256` values" in entry
    assert "fresh `proxySessionId` per writer" in entry
    assert "one log written into the stream twice rather than a restart" in entry
    assert "Session lines only" in entry


def test_the_readme_says_the_agreement_check_takes_one_log():
    """The consequence of allowing a restart, stated where the check is described."""
    prose = _flat(_c2_paragraph("The dashboard's terminal and attestation panes each have two"))
    assert "It takes one log" in prose
    assert "split at the session line" in prose


def test_the_readme_says_what_the_pane_carries_for_a_dropped_fragment():
    """The rule the test above pins has to be readable by whoever writes the harness.

    A harness author looking at a log with six lines and a pane with five has
    no way to tell which is right from the schema alone, so the contract says
    it: one event per framed line, none for the fragment, one for the recovery
    end line.
    """
    prose = _c2_paragraph("The pane carries one `attestation_appended` per line")
    assert "short-write fragment is not one of them" in prose
    assert "attestation-io" in prose
    assert "recovery `end` line" in prose and "does get its own" in prose
    assert "line-count difference" in prose


def test_the_agreement_key_separates_a_float_or_bool_seq_from_an_int():
    """Defense in depth, reached directly because the pre-validation refuses a float first.

    1 == 1.0 and 0 == False in Python, so a comparison on bare values would let
    a live pane rendering "1.0" certify as agreeing with a log rendering "1".
    check_events and check_attestation both refuse those before the comparison
    runs, which is why this is asserted on the key itself: if either rule is
    ever relaxed, the comparison must not be the thing that quietly stopped
    caring.
    """
    h = "a" * 64
    assert checks._pane_key("server", 1, h) == checks._pane_key("server", 1, h)
    assert checks._pane_key("server", 1, h) != checks._pane_key("server", 1.0, h)
    assert checks._pane_key("server", 0, h) != checks._pane_key("server", False, h)


# The agreement check validates three things before it compares anything: the
# log's framing, the log against C3, and the stream against C2. Each case below
# would compare as agreeing, so dropping any one of the three would pass it.

def test_the_agreement_check_refuses_a_log_it_cannot_frame():
    text = _pane_stream(ATTEST_TEXT)
    errs = checks.check_attestation_agreement(ATTEST_TEXT + "garbage\n", _parse(text))
    assert any("attestation: line 6:" in e for e in errs), errs


def test_the_agreement_check_runs_the_c3_rules_on_the_log():
    # Two session lines in one log, which C3 forbids. Distinct ones, so the
    # stream derived from them is valid C2 and only the C3 rule can object.
    lines = [json.loads(ln) for ln in ATTEST_TEXT.splitlines()]
    doubled = _c3_text([lines[0],
                        dict(lines[0], proxySessionId="9f1e6a2c-0b4d-4f6a-8c3e-1d5b7a9f0c22")])
    text = _pane_stream(doubled, outcome="aborted")
    assert checks.check_events_text(text) == []
    errs = checks.check_attestation_agreement(doubled, _parse(text))
    assert any("second session line" in e for e in errs), errs


def test_the_agreement_check_runs_the_c2_rules_on_the_stream():
    # A bare pane with no run_started and no run_finished around it.
    text = c2_stream(*_pane_events_from_log_text(ATTEST_TEXT, SERVER))
    errs = checks.check_attestation_agreement(ATTEST_TEXT, _parse(text))
    assert any("the first event must be run_started" in e for e in errs), errs


# Additive means additive. These are the type names and enum values C2 carried
# before 1.3.0, and every one of them must still be accepted.

_TYPES_1_1_0 = {"attention_frame", "beat", "component_assembled", "cxbom_emitted", "exfil_attempt",
                "gate_decision", "inbox_received", "lock_checked", "mcp_message", "model_delta",
                "run_finished", "run_started", "tool_approved", "tool_call", "tool_listed",
                "tool_swapped"}
_TYPES_1_2_0 = _TYPES_1_1_0 | {"launch_refused"}
_SIDECAR_TYPES_1_2_0 = {"mcp_message", "tool_listed", "lock_checked", "tool_swapped",
                        "gate_decision", "launch_refused"}


def test_the_1_2_0_example_still_passes_whole():
    """The committed example is the file 1.2.0 shipped, checked bytes and chain.

    Named on its own so a byte-level regression in the example reports as that,
    rather than as one assertion inside the broader additivity test below.
    """
    assert checks.check_events_text((C / "events/example-rug-pull-gate-on.events.jsonl").read_text()) == []
    assert checks.check_events(EVENTS) == []


def test_every_1_1_0_and_1_2_0_example_still_validates_under_1_3_0():
    merged = json.loads((C / "events" / "event.schema.json").read_text(encoding="utf-8"))
    sidecar = json.loads((C / "events" / "sidecar-event.schema.json").read_text(encoding="utf-8"))
    assert "1.4.0" in merged["$id"] and "1.4.0" in sidecar["$id"]
    assert _TYPES_1_2_0 <= set(merged["properties"]["type"]["enum"])
    assert _SIDECAR_TYPES_1_2_0 <= set(sidecar["properties"]["type"]["enum"])
    # The committed example passes whole in test_the_1_2_0_example_still_passes_whole.
    # The 1.2.0 additions: the launch-pin scenario and launch_refused in both schemas.
    ev = copy.deepcopy(EVENTS)
    ev[0]["data"]["scenario"] = "launch-pin"
    assert checks.check_events(ev) == []
    assert checks.check_sidecar_events([_launch_refused()]) == []
    assert checks.check_events(_launch_refused_in_merged_stream()) == []
    # Every outcome 1.1.0 named is still an outcome.
    for outcome in ("exfiltrated", "blocked", "no-attack"):
        assert checks.check_events_text(c2_stream(STARTED, ("run_finished", {"outcome": outcome}))) == []


def _launch_refused_in_merged_stream() -> list[dict]:
    ev = copy.deepcopy(EVENTS)
    frame = {"v": 1, "t": ev[0]["t"], "run": ev[0]["run"], "type": "launch_refused",
             "data": dict(LAUNCH_REFUSED_DATA), "prev_sha256": "a" * 64}
    ev.insert(1, frame)
    for i, e in enumerate(ev):
        e["seq"] = i
    return ev


def _c2_section() -> str:
    readme = (C / "README.md").read_text(encoding="utf-8")
    start = readme.index("## C2 demo events")
    return readme[start:readme.index("\n## ", start + 1)]


def _c2_block(name: str) -> dict:
    merged = json.loads((C / "events" / "event.schema.json").read_text(encoding="utf-8"))
    return next(b for b in merged["allOf"] if b["if"]["properties"]["type"]["const"] == name)


def _c2_row(typ: str) -> str:
    return next(ln for ln in _c2_section().splitlines() if ln.startswith(f"| `{typ}` |"))


def _c2_paragraph(opening: str) -> str:
    """One paragraph of the C2 section, found by its opening words.

    The table row and the prose paragraph each have to carry the convention on
    their own. A reader who lands on one does not necessarily read the other,
    and a section-wide substring search would let either go stale while the
    other kept the test green.
    """
    section = _c2_section()
    start = section.index(opening)
    return section[start:section.index("\n\n", start)]


def _c2_bullet(opening: str) -> str:
    """One bullet of the C2 section, found by its opening words.

    Same scoping argument as _c2_paragraph. A bullet list has no blank line
    between items, so the slice ends at the next bullet, blank line or heading.
    """
    section = _c2_section()
    start = section.index(opening)
    rest = section[start + len(opening):]
    m = re.search(r"\n(?=- |\n|#)", rest)
    return section[start:start + len(opening) + (m.start() if m else len(rest))]


def _flat(text: str) -> str:
    """Collapse whitespace so a claim can be asserted without minding line wrapping."""
    return re.sub(r"\s+", " ", text)


def test_the_readme_documents_every_c2_type_and_outcome():
    """A type the schema accepts and the README never names is undocumented drift."""
    section = _c2_section()
    assert "contracts/events/1.4.0" in section
    assert re.search(r"^### 1\.3\.0$", section, re.M), "the C2 version history has no 1.3.0 entry"
    merged = json.loads((C / "events" / "event.schema.json").read_text(encoding="utf-8"))
    for typ in merged["properties"]["type"]["enum"]:
        assert f"| `{typ}` |" in section, f"{typ} has no row in the C2 type table"
    outcomes = _c2_block("run_finished")["then"]["properties"]["data"]["properties"]["outcome"]["enum"]
    row = _c2_row("run_finished")
    for outcome in outcomes:
        assert f"`{outcome}`" in row, f"{outcome} is missing from the run_finished row"


def test_the_readme_names_every_run_started_scenario():
    """Schema-driven, so a seventh scenario with no row fails here rather than later."""
    enum = _c2_block("run_started")["then"]["properties"]["data"]["properties"]["scenario"]["enum"]
    assert {"benign-update", "malicious-at-approval"} <= set(enum)
    row = _c2_row("run_started")
    for scenario in enum:
        assert f"`{scenario}`" in row, f"{scenario} is missing from the run_started row"


def test_the_readme_says_what_the_honest_pair_of_scenarios_is_for():
    """Two values whose whole reason for existing is a claim about what pinning does.

    A name in an enum teaches nothing. benign-update only earns its place if the
    prose says the block is correct by rule and wrong by intent, and
    malicious-at-approval only if the prose says the gate never fires. Pinned in
    the body paragraph and in the version-history entry separately, because a
    reader meets one or the other.
    """
    prose = _flat(_c2_paragraph("`run_started.scenario` names which staged story"))
    assert "legitimate version bump whose tool description changed" in prose
    assert "false-positive cost of pinning a description" in prose
    assert "not caught at all" in prose and "the pin holds because the tool never changed" in prose
    assert "gate: enforce" in prose

    entry = _flat(_c2_bullet("- Added `benign-update` and `malicious-at-approval` to"))
    assert "false-positive cost" in entry
    assert "the pin holds and the gate never fires" in entry


def test_the_readme_states_that_outcome_conflates_a_block_with_a_false_positive():
    """The premortem finding, recorded as a limit and not closed.

    outcome has no value that separates a correctly blocked attack from a
    correctly-by-rule blocked legitimate update, so a published file cannot be
    read for that distinction. Stating it is the whole control, since no field
    carries it, and the statement has to name where the distinction does live.
    """
    prose = _flat(_c2_paragraph(
        "**A blocked legitimate update and a blocked attack carry the same `outcome`.**"))
    assert "conflates a true positive with a false positive" in prose
    assert "not recoverable from `outcome`" in prose
    assert "`run_started.scenario`" in prose and "`gate_decision`'s `reason`" in prose
    assert "adds no outcome value for this" in prose

    entry = _flat(_c2_bullet("- Added `benign-update` and `malicious-at-approval` to"))
    assert "cannot tell a blocked `benign-update` from a blocked `rug-pull`" in entry
    assert "no outcome value is added for it here" in entry


@pytest.mark.parametrize("typ", ["attestation_appended", "proxy_exited", "proxy_stderr"])
def test_the_readme_row_names_every_required_field_of_the_new_events(typ):
    """A field added under additionalProperties: false is frozen, so the row names it."""
    row = _c2_row(typ)
    for field in _c2_block(typ)["then"]["properties"]["data"]["required"]:
        assert f"`{field}`" in row, f"{typ}.{field} is missing from its README row"


def test_the_readme_states_the_exit_code_range_and_the_signal_mapping():
    """The schema pins the bounds; only the prose can pin the convention.

    Two harnesses reading a signal kill from two runtimes encode it two ways
    unless the contract names one, and a schema cannot say "map it to 128 + N
    first". Pinned because that is the whole point of writing it down, and
    pinned in both places a reader meets it, so neither can go stale behind
    the other.
    """
    for where in (_c2_row("proxy_exited"), _c2_paragraph("`proxy_exited.exitCode` is")):
        assert "0 to 255" in where, where
        assert "128 + N" in where, where
    prose = _c2_paragraph("`proxy_exited.exitCode` is")
    for signal, code in (("SIGTERM", "143"), ("SIGKILL", "137")):
        assert signal in prose and code in prose, signal


def test_the_replay_publish_list_names_every_free_text_field_the_panes_add():
    """The two new free-text fields are copied out of another process's output.

    That is where an unscrubbed canary reaches a published file without anyone
    choosing to put it there, so the publish-safety list has to name them.
    """
    section = _c2_section()
    start = section.index("### Replay on cxbom.org")
    replay = section[start:section.index("\n### ", start + 1)]
    for field in ("`mcp_message.summary`", "`tool_swapped.descriptionDiff`",
                  "`proxy_stderr.text`", "`attestation_appended.summary`"):
        assert field in replay, f"{field} is not in the publish-safety list"
    assert "`<canary>`" in replay
    assert "never published in clear" in replay


# --- C2 1.3.1: the collector merge rule and the non-url canary question (M-4) ---


def test_the_readme_carries_a_1_3_1_version_history_entry():
    """The bump is real: header label, a version-history entry, and the patch note."""
    section = _c2_section()
    assert "contracts/events/1.4.0" in section
    assert re.search(r"^### 1\.3\.1$", section, re.M), "the C2 version history has no 1.3.1 entry"
    # The 1.3.0 entry is history and stays, so a reader upgrading step by step
    # still finds it.
    assert re.search(r"^### 1\.3\.0$", section, re.M), "the 1.3.0 history entry was dropped"
    intro = _flat(_c2_paragraph("Patch, documentation only."))
    assert "Every 1.3.0 line and example stays valid" in intro
    assert "no consumer breaks" in intro


def test_the_readme_documents_the_collector_merge_rule():
    """The five parts of the merge rule, with the stale wall-clock wording gone.

    A harness author building the collector reads this to learn the order the
    merged stream must be written in. The rule changed, so the old wording (a
    null-session line placed by its wall-clock `at`) has to be absent, not just
    joined by the new text: the last assertion flips for a mutant that restores
    the earlier paragraph.
    """
    opening = _flat(_c2_paragraph("Proxies do not write the merged stream."))
    assert "one live writer of the merged stream" in opening
    assert "drains every open sidecar before it writes each of the demo's own events" in opening

    body = _flat(_c2_paragraph("Within one session the order is"))
    assert "the order is the sidecar's file order, which equals its `mono` order" in body
    assert "the collector verifies the two agree" in body
    assert "Across sessions the order is drain order" in body
    assert "the sessions read in one drain attach in the order that drain read them" in body
    assert "Each null-session line lands at the drain that reads it" in body
    assert "The merged file and its `prev_sha256` chain are the record" in body

    assert "wall-clock" not in _c2_section(), "the stale null-session ordering wording is still here"


def test_the_readme_1_3_1_entry_answers_the_non_url_canary_question():
    """The M-4 decision, pinned where a consumer upgrading from 1.3.0 meets it.

    exfil_attempt stays url-only by design, so the entry has to say what reports
    a non-url canary instead and why exfil_attempt is not stretched to cover it,
    or it is a claim with no rule behind it.
    """
    entry = _flat(_c2_bullet("- Answered how C2 reports a keyed canary"))
    assert "keeps its required `url`" in entry
    assert "network exfiltration channel" in entry
    assert "non-url argument is a rule violation, not a network exfiltration" in entry
    assert "reports it through the redacted `tool_call.arguments`" in entry
    assert "not repurposed for a non-url argument" in entry
    assert "1.4.0, not 1.3.1" in entry


# exfil_attempt reports the network exfiltration channel, so its url is required
# and the schema forbids extra fields. A keyed canary in a tool-call argument
# that is not a url is a rule violation, not an exfiltration, and C2 reports it
# through the redacted tool_call.arguments rather than through a urless
# exfil_attempt. These pin the schema half of that decision, each aimed at one
# constraint so a mutant that relaxes it flips exactly one test.

_EXFIL_OK = {"tool": "fetch", "url": "http://inbox.test/?k=<canary>", "canaryPresent": True}


def test_exfil_attempt_with_a_url_validates():
    # Positive control: a rejection below is the missing or extra field, not a
    # malformed fixture.
    assert _one_event_errs("exfil_attempt", _EXFIL_OK) == []


def test_exfil_attempt_without_a_url_is_refused():
    # The M-4 case: a keyed canary in a non-url argument cannot be reported as
    # an exfil_attempt, because the url that carries the secret off the box is
    # not optional. Relaxing url to optional in the schema would pass this.
    errs = _one_event_errs("exfil_attempt", _without(_EXFIL_OK, "url"))
    assert any("'url' is a required property" in e for e in errs), errs


def test_exfil_attempt_forbids_a_bolted_on_non_url_channel_field():
    # additionalProperties is false, so a non-url location cannot be bolted onto
    # exfil_attempt either. Setting additionalProperties true would pass this.
    errs = _one_event_errs("exfil_attempt", dict(_EXFIL_OK, field="query"))
    assert any("Additional properties are not allowed" in e for e in errs), errs


def test_a_non_url_canary_is_carried_by_tool_call_arguments():
    # The chosen representation: the redacted argument reads <canary> in the
    # offending non-url field. tool_call.arguments is an open object, so the
    # marker rides in it directly, and the run's canary containment
    # (cxbom.canary) keeps the clear value out of the stream. A schema that
    # closed tool_call.arguments to a fixed key set would break this.
    errs = _one_event_errs("tool_call",
                           {"tool": "search_notes", "arguments": {"query": "<canary>"}})
    assert errs == []
