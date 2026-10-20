"""Lock discovery, reading, and envelope verification (spec 6). Owner: ATACE Working Group."""
import copy
import json
from pathlib import Path

import pytest

from cxbom import lockfile, signing
from cxbom.timeutil import parse_time

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "contracts/proxy/example.cxbom.lock"
NOW = parse_time("2026-10-10T19:00:00Z")


@pytest.fixture
def trusted_example(tmp_path):
    import sys
    sys.path.insert(0, str(ROOT / "contracts/proxy"))
    import make_example
    pub = (ROOT / "contracts/proxy/example-key.pub").read_text().strip()
    raw = signing.decode_pub(pub)
    fp = signing.fingerprint(raw)
    return {fp: signing.TrustedKey(signing.PublicKey(fp, raw), None)}, make_example.example_key()


def test_find_lock_precedence(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "cxbom.lock").write_text("{}")
    assert lockfile.find_lock(tmp_path / "a" / "b", None, {}) == tmp_path / "cxbom.lock"
    explicit = tmp_path / "x.lock"
    assert lockfile.find_lock(tmp_path, explicit, {"CXBOM_LOCK": "/nope"}) == explicit
    assert lockfile.find_lock(tmp_path, None, {"CXBOM_LOCK": str(explicit)}) == explicit
    with pytest.raises(lockfile.LockError):
        lockfile.find_lock(Path("/"), None, {})


def test_read_and_verify_example(tmp_path, trusted_example):
    trusted, _ = trusted_example
    lock = lockfile.read_lock(EXAMPLE)
    ve = lockfile.verified_entry(lock, "fetch", trusted, tmp_path / "state", NOW, update_highwater=True)
    assert ve.entry_seq == 1 and ve.entry["renderer"] == "jcs"


def test_unknown_server_is_not_approved(tmp_path, trusted_example):
    trusted, _ = trusted_example
    with pytest.raises(lockfile.LockError, match="not-approved"):
        lockfile.verified_entry(lockfile.read_lock(EXAMPLE), "other", trusted, tmp_path / "s", NOW, True)


def test_rollback_refused(tmp_path, trusted_example):
    trusted, key = trusted_example
    lock = lockfile.read_lock(EXAMPLE)
    newer = copy.deepcopy(lock)
    env = newer["servers"]["fetch"]["envelope"]
    env["entrySeq"] = 5
    newer["servers"]["fetch"]["signature"] = signing.sign_envelope(key, env)
    state = tmp_path / "state"
    lockfile.verified_entry(newer, "fetch", trusted, state, NOW, update_highwater=True)
    with pytest.raises(lockfile.LockError, match="rollback"):
        lockfile.verified_entry(lock, "fetch", trusted, state, NOW, update_highwater=True)


def test_scope_mismatch_refused(tmp_path, trusted_example):
    trusted, _ = trusted_example
    lock = lockfile.read_lock(EXAMPLE)
    lock["lockScope"] = "f" * 32
    with pytest.raises(lockfile.LockError, match="lockScope"):
        lockfile.verified_entry(lock, "fetch", trusted, tmp_path / "s", NOW, True)


def test_write_is_canonical(tmp_path):
    lock = lockfile.new_lock("a" * 32)
    p = tmp_path / "cxbom.lock"
    lockfile.write_lock(p, lock)
    assert p.read_text() == json.dumps(lock, indent=2, sort_keys=True) + "\n"


def test_read_lock_invalid_json(tmp_path):
    p = tmp_path / "bad.lock"
    p.write_text("{ invalid json }")
    with pytest.raises(lockfile.LockError, match="not strict JSON"):
        lockfile.read_lock(p)


def test_read_lock_schema_violation(tmp_path):
    p = tmp_path / "bad.lock"
    lock = lockfile.read_lock(EXAMPLE)
    lock["extra_field"] = "not_allowed"
    p.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    with pytest.raises(lockfile.LockError, match="lock fails C3 2.0.0"):
        lockfile.read_lock(p)


def test_read_lock_non_canonical_form(tmp_path):
    p = tmp_path / "noncanonical.lock"
    lock = lockfile.read_lock(EXAMPLE)
    p.write_text(json.dumps(lock))
    with pytest.raises(lockfile.LockError, match="lock is not in canonical form"):
        lockfile.read_lock(p)


def test_read_lock_missing_path(tmp_path):
    p = tmp_path / "nonexistent.lock"
    with pytest.raises(lockfile.LockError, match="cannot read lock"):
        lockfile.read_lock(p)


def test_verified_entry_missing_signature(tmp_path, trusted_example):
    trusted, _ = trusted_example
    lock = copy.deepcopy(lockfile.read_lock(EXAMPLE))
    del lock["servers"]["fetch"]["signature"]
    with pytest.raises(lockfile.LockError, match="lock fails C3 2.0.0"):
        lockfile.verified_entry(lock, "fetch", trusted, tmp_path / "s", NOW, True)


def test_write_lock_atomic_and_mode(tmp_path):
    lock = lockfile.new_lock("a" * 32)
    p = tmp_path / "cxbom.lock"
    lockfile.write_lock(p, lock)
    assert p.exists()
    assert len(list(tmp_path.glob("*"))) == 1
    assert (p.stat().st_mode & 0o777) == 0o644


# --- Final review B1: strict parsing of lock bytes ---


def _deep(n):
    v = []
    for _ in range(n):
        v = [v]
    return v


def _lock_text_with_server_info(info) -> str:
    doc = json.loads(EXAMPLE.read_text())
    doc["servers"]["fetch"]["envelope"]["entry"]["eras"]["legacy"]["serverInfo"] = info
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def _dup_key_text() -> str:
    text = EXAMPLE.read_text()
    return text.replace('"canonicalization":', '"lockScope": "0",\n  "canonicalization":', 1)


STRICT_CASES = {
    "nan": (lambda: _lock_text_with_server_info({"x": float("nan")}), "strict JSON"),
    "infinity": (lambda: _lock_text_with_server_info({"x": float("inf")}), "strict JSON"),
    "big-int": (lambda: _lock_text_with_server_info({"x": 2**53 + 1}), "2**53"),
    "negative-big-int": (lambda: _lock_text_with_server_info({"x": -(2**53) - 1}), "2**53"),
    "duplicate-key": (_dup_key_text, "duplicate key"),
    "deep-nesting": (lambda: _lock_text_with_server_info({"x": _deep(200)}), "nesting"),
}


@pytest.mark.parametrize("case", sorted(STRICT_CASES))
def test_read_lock_rejects_non_strict_json(tmp_path, case):
    make, needle = STRICT_CASES[case]
    p = tmp_path / "cxbom.lock"
    p.write_text(make())
    with pytest.raises(lockfile.LockError, match=needle.replace("*", r"\*")):
        lockfile.read_lock(p)


def test_read_lock_accepts_integer_at_the_2_53_bound(tmp_path):
    p = tmp_path / "cxbom.lock"
    p.write_text(_lock_text_with_server_info({"x": 2**53}))
    assert lockfile.read_lock(p)["servers"]["fetch"]


def test_read_lock_caps_input_at_one_mib(tmp_path):
    p = tmp_path / "cxbom.lock"
    p.write_text(_lock_text_with_server_info({"x": "a" * (1024 * 1024)}))
    with pytest.raises(lockfile.LockError, match="exceeds"):
        lockfile.read_lock(p)


# --- Final review B2: error types out of verified_entry ---


def test_verified_entry_uncanonicalizable_envelope_is_lock_error(tmp_path, trusted_example):
    trusted, _ = trusted_example
    lock = copy.deepcopy(lockfile.read_lock(EXAMPLE))
    lock["servers"]["fetch"]["envelope"]["entrySeq"] = 2**60   # schema-valid, outside I-JSON
    with pytest.raises(lockfile.LockError):
        lockfile.verified_entry(lock, "fetch", trusted, tmp_path / "s", NOW, True)


def test_verified_entry_wraps_oserror_without_the_path(tmp_path, trusted_example, monkeypatch):
    import errno
    trusted, _ = trusted_example

    def boom(*a, **k):
        raise OSError(errno.EIO, "Input/output error", str(tmp_path / "state" / "highwater.json"))

    monkeypatch.setattr(signing, "check_highwater", boom)
    with pytest.raises(lockfile.LockError) as ei:
        lockfile.verified_entry(lockfile.read_lock(EXAMPLE), "fetch", trusted, tmp_path / "state", NOW, True)
    assert str(tmp_path) not in str(ei.value)
    assert "Input/output error" in str(ei.value)


def test_verified_entry_lets_path_security_error_propagate(tmp_path, trusted_example):
    from cxbom.paths import PathSecurityError
    trusted, _ = trusted_example
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "state"
    link.symlink_to(real)
    with pytest.raises(PathSecurityError):
        lockfile.verified_entry(lockfile.read_lock(EXAMPLE), "fetch", trusted, link, NOW, True)


def test_verified_entry_naive_now_is_lock_error(tmp_path, trusted_example):
    trusted, _ = trusted_example
    with pytest.raises(lockfile.LockError, match="time zone"):
        lockfile.verified_entry(lockfile.read_lock(EXAMPLE), "fetch", trusted, tmp_path / "s",
                                NOW.replace(tzinfo=None), True)


def test_lockfile_requires_format_checkers():
    from jsonschema import FormatChecker
    with pytest.raises(RuntimeError, match="date-time"):
        lockfile._require_formats(FormatChecker(formats=["uuid"]))
    with pytest.raises(RuntimeError, match="uuid"):
        lockfile._require_formats(FormatChecker(formats=["date-time"]))
    lockfile._require_formats(FormatChecker())


# --- Final review F2 ---


def test_entry_signed_for_another_server_is_refused_under_this_key(tmp_path, trusted_example):
    trusted, key = trusted_example
    lock = copy.deepcopy(lockfile.read_lock(EXAMPLE))
    env = lock["servers"]["fetch"]["envelope"]
    env["serverId"] = "other"        # server B's entry, validly signed by a trusted key
    lock["servers"]["fetch"]["signature"] = signing.sign_envelope(key, env)
    with pytest.raises(lockfile.LockError, match="serverId"):
        lockfile.verified_entry(lock, "fetch", trusted, tmp_path / "s", NOW, True)
