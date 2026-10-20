"""Enforcement state shared by proxy and emitter (spec 8.5). Owner: ATACE Working Group."""
import pytest

from cxbom import state as st

T = "2026-10-10T18:05:00Z"

SESSION = {"kind": "session", "contract": {"name": "cxbom-attestation", "version": "2.0.0"},
           "proxySessionId": "3b0c8f0e-6c1c-4b8e-9d5e-2f7a1c9e0b11", "serverId": "fetch", "mode": "enforce",
           "startedAt": T, "pid": 1, "envelopeSha256": "a" * 64, "keyFingerprint": "b" * 64,
           "launchSha256": "c" * 64}


def server(seq, verdict="pinned-match"):
    return {"kind": "server", "seq": seq, "at": T, "instructionsSha256": "a" * 64,
            "serverInfo": {}, "verdict": verdict, "storeRef": None}


def verdict(seq, name, v="pinned-match", sha="b" * 64):
    return {"kind": "verdict", "seq": seq, "at": T, "itemType": "tool", "name": name, "sha256": sha,
            "verdict": v, "approvedBy": "op", "approvedAt": T, "approvalMode": "interactive", "storeRef": None}


def statel(seq, name, s, item="tool", cause="list_changed"):
    return {"kind": "state", "seq": seq, "at": T, "itemType": item, "name": name, "state": s, "cause": cause}


def test_allowed_needs_verified_instructions():
    s = st.compute([SESSION, verdict(1, "fetch")])
    assert st.lookup(s, "tool", "fetch").state == st.UNVERIFIED
    s = st.compute([SESSION, server(1), verdict(2, "fetch")])
    assert st.lookup(s, "tool", "fetch").state == st.ALLOWED


def test_changed_instructions_block_everything():
    s = st.compute([SESSION, server(1), verdict(2, "fetch"), server(3, "changed"), verdict(4, "other")])
    assert st.lookup(s, "tool", "fetch").state == st.BLOCKED
    assert st.lookup(s, "tool", "other").state == st.BLOCKED


def test_changed_tool_blocked_and_state_overrides():
    s = st.compute([SESSION, server(1), verdict(2, "fetch", "changed", sha="c" * 64)])
    assert st.lookup(s, "tool", "fetch").state == st.BLOCKED
    s = st.compute([SESSION, server(1), verdict(2, "fetch"), statel(3, "*", st.UNVERIFIED)])
    assert st.lookup(s, "tool", "fetch").state == st.UNVERIFIED


def test_default_not_listed_and_itemtype_isolation():
    s = st.compute([SESSION, server(1), dict(verdict(2, "fetch"), itemType="prompt")])
    assert st.lookup(s, "tool", "fetch").state == st.NOT_LISTED
    assert st.lookup(s, "prompt", "fetch").state == st.ALLOWED


def test_state_line_with_allowed_state_raises():
    # Spec 8.5: allowed only comes from a pinned-match verdict with verified
    # instructions. A state line asking for it directly is a malformed log.
    with pytest.raises(st.StateError):
        st.compute([SESSION, server(1), verdict(2, "fetch"), statel(3, "fetch", st.ALLOWED)])


def test_invalid_log_raises_state_error_from_both_functions():
    lines = [SESSION, server(1), verdict(3, "fetch")]  # seq gap: 1 then 3
    with pytest.raises(st.StateError):
        st.compute(lines)
    with pytest.raises(st.StateError):
        st.instructions_verified(lines)


def test_pinned_match_after_changed_leaves_prior_blocked_but_allows_new():
    s = st.compute([
        SESSION,
        server(1),
        verdict(2, "fetch"),
        server(3, "changed"),
        verdict(4, "other"),
        server(5),
        verdict(6, "newtool"),
    ])
    assert st.lookup(s, "tool", "fetch").state == st.BLOCKED
    assert st.lookup(s, "tool", "other").state == st.BLOCKED
    assert st.lookup(s, "tool", "newtool").state == st.ALLOWED


def test_state_line_creates_unseen_item():
    s = st.compute([SESSION, statel(1, "unseen-tool", st.BLOCKED)])
    item = st.lookup(s, "tool", "unseen-tool")
    assert item.state == st.BLOCKED
    assert item.seq == 1
    assert item.cause == "list_changed"


def test_wildcard_state_line_overrides_every_type():
    s = st.compute([
        SESSION,
        server(1),
        verdict(2, "fetch"),
        dict(verdict(3, "fetch"), itemType="prompt"),
        statel(4, "*", st.BLOCKED, item="*"),
    ])
    assert st.lookup(s, "tool", "fetch").state == st.BLOCKED
    assert st.lookup(s, "prompt", "fetch").state == st.BLOCKED


def test_changed_then_pinned_match_verdict_restores_item():
    s = st.compute([SESSION, server(1), verdict(2, "fetch", "changed", sha="c" * 64), verdict(3, "fetch")])
    assert st.lookup(s, "tool", "fetch").state == st.ALLOWED


def test_instructions_verified_tracks_the_latest_server_line():
    assert st.instructions_verified([SESSION, verdict(1, "fetch")]) is False
    assert st.instructions_verified([SESSION, server(1), verdict(2, "fetch"), server(3, "changed")]) is False
    assert st.instructions_verified([SESSION, server(1)]) is True


def test_named_state_line_touches_only_that_type_and_name():
    s = st.compute([SESSION, server(1), verdict(2, "fetch"), verdict(3, "other"),
                    dict(verdict(4, "fetch"), itemType="prompt"), statel(5, "fetch", st.BLOCKED)])
    assert st.lookup(s, "tool", "fetch").state == st.BLOCKED
    assert st.lookup(s, "tool", "other").state == st.ALLOWED
    assert st.lookup(s, "prompt", "fetch").state == st.ALLOWED


def test_uncanonicalizable_verdict_with_null_sha_is_blocked():
    line = dict(verdict(2, "fetch", v="uncanonicalizable"), sha256=None)
    s = st.compute([SESSION, server(1), line])
    item = st.lookup(s, "tool", "fetch")
    assert (item.state, item.sha256) == (st.BLOCKED, None)
