"""Enforcement state computed from an attestation log.

Owner: ATACE Working Group.

The proxy and the emitter use this one function, so a record can never
disagree with what the proxy enforced (premortem B-series, "record says allowed
while proxy blocked"). Items are keyed by (itemType, name), so a prompt named
"fetch" cannot shadow the tool "fetch".

compute() and instructions_verified() both run the log through
attestation.check_log() first, so an invalid log (a schema failure, a seq
gap, a second session line) never reaches the state logic and gets read as
if it meant something. A state line never grants allowed: spec 8.5 defines
allowed only through a pinned-match verdict with verified instructions. The
C3 2.0.0 schema leaves "allowed" out of the state line's enum, so check_log
rejects such a line and compute() raises StateError for it.

The proxy writes the server line before any verdict line (spec 8.5). A
pinned-match verdict that arrives before any server line stays unverified.

compute() applies lines in log order, and the latest line for an item wins.
It cannot see chains, so the proxy that writes the log carries spec 8.5's
chain rules. The proxy never writes verdict lines from a superseded chain.
It writes duplicate-name as the last verdict for that name in a chain. It
writes a state not-listed line for every item absent after a full chain. It
refuses items literally named "*", since "*" is the wildcard here. The era
latch never changes within one log (spec 8.3).
"""
from __future__ import annotations

from dataclasses import dataclass

from . import attestation

NOT_LISTED = "not-listed"
ALLOWED = "allowed"
BLOCKED = "blocked"
UNVERIFIED = "unverified"
PINNED_MATCH = "pinned-match"

# Keep the raised message short: a log with many bad lines should not dump
# its whole error list into an exception a caller might log verbatim.
_MAX_ERRORS_SHOWN = 3


class StateError(ValueError):
    """The attestation log is invalid, or a line asks for a state it cannot grant."""


@dataclass(frozen=True)
class ItemState:
    item_type: str
    name: str
    state: str
    sha256: str | None
    seq: int | None
    verdict: str | None
    cause: str


def _validate(lines: list[dict]) -> None:
    errs = attestation.check_log(lines)
    if errs:
        raise StateError("attestation log invalid: " + "; ".join(errs[:_MAX_ERRORS_SHOWN]))


def compute(lines: list[dict]) -> dict[tuple[str, str], ItemState]:
    _validate(lines)
    states: dict[tuple[str, str], ItemState] = {}
    # None until a server line is seen, then holds that line's verdict.
    instructions: str | None = None

    def block_all(cause: str, seq: int) -> None:
        for key, item in list(states.items()):
            states[key] = ItemState(item.item_type, item.name, BLOCKED, item.sha256, seq, item.verdict, cause)

    for line in lines:
        kind = line.get("kind")
        if kind == "server":
            instructions = line["verdict"]
            if instructions != PINNED_MATCH:
                block_all("instructions", line["seq"])
        elif kind == "verdict":
            key = (line["itemType"], line["name"])
            v = line["verdict"]
            if v != PINNED_MATCH:
                item_state, cause = BLOCKED, v
            elif instructions is None:
                item_state, cause = UNVERIFIED, "instructions-not-seen"
            elif instructions != PINNED_MATCH:
                item_state, cause = BLOCKED, "instructions"
            else:
                item_state, cause = ALLOWED, v
            states[key] = ItemState(key[0], key[1], item_state, line["sha256"], line["seq"], v, cause)
        elif kind == "state":
            # The schema already refuses this. The check stays as a second layer
            # because a state line granting allowed would bypass the pin.
            if line["state"] == ALLOWED:
                raise StateError("a state line cannot grant allowed")
            it, name = line["itemType"], line["name"]
            for key, item in list(states.items()):
                if it in ("*", key[0]) and name in ("*", key[1]):
                    states[key] = ItemState(
                        item.item_type, item.name, line["state"], item.sha256, line["seq"],
                        item.verdict, line["cause"])
            if name != "*" and it != "*" and (it, name) not in states:
                states[(it, name)] = ItemState(it, name, line["state"], None, line["seq"], None, line["cause"])
    return states


def lookup(states: dict[tuple[str, str], ItemState], item_type: str, name: str) -> ItemState:
    return states.get((item_type, name), ItemState(item_type, name, NOT_LISTED, None, None, None, "not-listed"))


def instructions_verified(lines: list[dict]) -> bool:
    _validate(lines)
    servers = [line for line in lines if line.get("kind") == "server"]
    return bool(servers) and servers[-1]["verdict"] == PINNED_MATCH
