"""Keys, envelopes, trust manifest, high-water marks (spec 6). Owner: ATACE Working Group."""
import errno
import os
from datetime import timedelta

import pytest

from cxbom import signing
from cxbom.timeutil import parse_time

NOW = "2026-10-10T18:00:00Z"
PW = b"correct horse battery staple"


@pytest.fixture
def cfg(tmp_path):
    d = tmp_path / "config"
    signing.generate_key(PW, d, NOW)
    return d


def envelope(**over):
    env = {"serverId": "fetch", "lockScope": "0" * 32, "entrySeq": 1, "issuedAt": NOW, "notAfter": None,
           "entry": {"allowObserve": False, "allowSampling": False}}
    env.update(over)
    return env


def test_key_files_are_private(cfg):
    assert (os.stat(cfg / signing.KEY_FILE).st_mode & 0o777) == 0o600
    assert (os.stat(cfg).st_mode & 0o777) == 0o700


def test_wrong_passphrase(cfg):
    with pytest.raises(signing.SigningError):
        signing.load_private(b"wrong", cfg)


def test_sign_and_verify_envelope(cfg):
    key = signing.load_private(PW, cfg)
    env = envelope()
    sig = signing.sign_envelope(key, env)
    assert len(sig["sig"]) == 88 and sig["sig"].endswith("==")
    trusted = signing.load_trusted(cfg)
    fp = signing.verify_envelope(env, sig, trusted, parse_time(NOW))
    assert fp == signing.load_own_public(cfg).fingerprint


def test_tampered_envelope_fails(cfg):
    key = signing.load_private(PW, cfg)
    env = envelope()
    sig = signing.sign_envelope(key, env)
    env["entry"]["allowObserve"] = True
    with pytest.raises(signing.SigningError):
        signing.verify_envelope(env, sig, signing.load_trusted(cfg), parse_time(NOW))


@pytest.mark.parametrize("flag", ["allowObserve", "allowSampling"])
def test_permissive_entry_with_no_not_after_never_expires(cfg, flag):
    # Owner decision 2026-10-05: the tool sets no lifetime on an observe or
    # sampling entry. Only an owner-set notAfter ends it.
    key = signing.load_private(PW, cfg)
    trusted = signing.load_trusted(cfg)
    env = envelope(entry={"allowObserve": False, "allowSampling": False, flag: True})
    sig = signing.sign_envelope(key, env)
    for later in (timedelta(0), timedelta(days=2), timedelta(days=3650)):
        assert signing.verify_envelope(env, sig, trusted, parse_time(NOW) + later)


def test_owner_set_not_after_still_expires(cfg):
    key = signing.load_private(PW, cfg)
    trusted = signing.load_trusted(cfg)
    ok = envelope(notAfter="2026-10-11T06:00:00Z", entry={"allowObserve": True, "allowSampling": False})
    signing.verify_envelope(ok, signing.sign_envelope(key, ok), trusted, parse_time(NOW))
    with pytest.raises(signing.SigningError, match="expired"):
        signing.verify_envelope(ok, signing.sign_envelope(key, ok), trusted,
                                parse_time(NOW) + timedelta(days=2))


def test_no_tty_no_passphrase(monkeypatch):
    def boom(*a, **k):
        raise OSError("no tty")
    monkeypatch.setattr(os, "open", boom)
    with pytest.raises(signing.SigningError):
        signing.read_passphrase("passphrase: ")


def test_signature_not_dict(cfg):
    key = signing.load_private(PW, cfg)
    env = envelope()
    sig = signing.sign_envelope(key, env)
    trusted = signing.load_trusted(cfg)
    with pytest.raises(signing.SigningError):
        signing.verify_envelope(env, None, trusted, parse_time(NOW))


def test_signature_missing_sig_field(cfg):
    key = signing.load_private(PW, cfg)
    env = envelope()
    trusted = signing.load_trusted(cfg)
    with pytest.raises(signing.SigningError):
        signing.verify_envelope(env, {"alg": "ed25519"}, trusted, parse_time(NOW))


def test_entry_not_dict(cfg):
    key = signing.load_private(PW, cfg)
    env = envelope(entry=[])
    with pytest.raises(signing.SigningError):
        signing.verify_envelope(env, signing.sign_envelope(key, env), signing.load_trusted(cfg), parse_time(NOW))


def test_missing_issuedAt(cfg):
    key = signing.load_private(PW, cfg)
    env = envelope(issuedAt=None)
    del env["issuedAt"]
    with pytest.raises(signing.SigningError):
        signing.verify_envelope(env, signing.sign_envelope(key, env), signing.load_trusted(cfg), parse_time(NOW))


def test_bad_base64_public_key(cfg):
    with pytest.raises(signing.SigningError):
        signing.decode_pub("ed25519:!!!invalid!!!")


def test_issuedAt_in_future(cfg):
    key = signing.load_private(PW, cfg)
    future_time = "2026-10-10T18:30:00Z"
    env = envelope(issuedAt=future_time)
    trusted = signing.load_trusted(cfg)
    with pytest.raises(signing.SigningError):
        signing.verify_envelope(env, signing.sign_envelope(key, env), trusted, parse_time(NOW))


def test_notAfter_before_issuedAt(cfg):
    key = signing.load_private(PW, cfg)
    env = envelope(issuedAt="2026-10-10T18:00:00Z", notAfter="2026-10-10T17:00:00Z")
    with pytest.raises(signing.SigningError):
        signing.verify_envelope(env, signing.sign_envelope(key, env), signing.load_trusted(cfg), parse_time(NOW))


def test_malformed_signature_fails(cfg):
    import base64

    key = signing.load_private(PW, cfg)
    env = envelope()
    sig_dict = signing.sign_envelope(key, env)
    trusted = signing.load_trusted(cfg)
    sig_b64 = sig_dict["sig"]
    pub_key = trusted[list(trusted.keys())[0]].pub

    assert signing.verify_obj(pub_key, env, sig_b64)

    sig_bytes = base64.b64decode(sig_b64, validate=True)
    assert len(sig_bytes) == 64

    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    sig_list = list(sig_b64)
    last_char = sig_b64[85]
    last_char_idx = base64_chars.index(last_char)
    new_char_idx = last_char_idx ^ 0x0F
    sig_list[85] = base64_chars[new_char_idx]
    non_canonical = "".join(sig_list)

    assert base64.b64decode(non_canonical, validate=True) == sig_bytes
    assert not signing.verify_obj(pub_key, env, non_canonical)


def test_atomic_write_cleanup_on_failure(tmp_path):
    target = tmp_path / "target"
    target.mkdir()                      # os.replace(file, existing_dir) must fail
    with pytest.raises(OSError) as info:
        signing._atomic_write(target, b"data")
    assert info.value.errno != errno.EBADF
    assert not any(p.name.startswith("target.") for p in tmp_path.iterdir())


def other_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return k, signing.encode_pub(raw)


def test_dropped_pub_file_is_not_trusted(cfg):
    k, pub = other_key()
    (cfg / "attacker.pub").write_text(pub)
    env = envelope()
    with pytest.raises(signing.SigningError):
        signing.verify_envelope(env, signing.sign_envelope(k, env), signing.load_trusted(cfg), parse_time(NOW))


def test_trust_add_requires_passphrase_and_extends_trust(cfg):
    k, pub = other_key()
    with pytest.raises(signing.SigningError):
        signing.trust_add(b"wrong", cfg, pub, NOW)
    fp = signing.trust_add(PW, cfg, pub, NOW)
    env = envelope()
    assert signing.verify_envelope(env, signing.sign_envelope(k, env), signing.load_trusted(cfg), parse_time(NOW)) == fp


def test_tampered_manifest_rejected(cfg):
    import json
    m = json.loads((cfg / signing.MANIFEST_FILE).read_text())
    _, pub = other_key()
    m["keys"].append({"fingerprint": "f" * 64, "publicKey": pub, "addedAt": NOW, "revokedAfter": None})
    (cfg / signing.MANIFEST_FILE).write_text(json.dumps(m))
    with pytest.raises(signing.SigningError):
        signing.load_trusted(cfg)


def test_revocation_rejects_later_entries(cfg):
    k, pub = other_key()
    fp = signing.trust_add(PW, cfg, pub, NOW)
    signing.trust_revoke(PW, cfg, fp, "2026-10-10T12:00:00Z")
    env = envelope()
    with pytest.raises(signing.SigningError):
        signing.verify_envelope(env, signing.sign_envelope(k, env), signing.load_trusted(cfg), parse_time(NOW))


def test_highwater_blocks_rollback(tmp_path):
    st = tmp_path / "state"
    signing.check_highwater(st, "0" * 32, "fetch", 3, update=True)
    signing.check_highwater(st, "0" * 32, "fetch", 3, update=True)
    with pytest.raises(signing.SigningError):
        signing.check_highwater(st, "0" * 32, "fetch", 2, update=True)
    signing.check_highwater(st, "1" * 32, "fetch", 1, update=False)


def test_highwater_corrupt_json(tmp_path):
    st = tmp_path / "state"
    signing.check_highwater(st, "0" * 32, "fetch", 1, update=True)
    hw_file = st / signing.HIGHWATER_FILE
    hw_file.write_text("{bad")
    with pytest.raises(signing.SigningError, match="corrupt"):
        signing.check_highwater(st, "0" * 32, "fetch", 2, update=True)
    hw_file.write_text("[]")
    with pytest.raises(signing.SigningError, match="corrupt"):
        signing.check_highwater(st, "0" * 32, "fetch", 2, update=True)


def test_highwater_invalid_seq_type(tmp_path):
    st = tmp_path / "state"
    with pytest.raises(signing.SigningError):
        signing.check_highwater(st, "0" * 32, "fetch", True, update=True)


def test_highwater_invalid_scope(tmp_path):
    st = tmp_path / "state"
    with pytest.raises(signing.SigningError):
        signing.check_highwater(st, "a/b", "fetch", 1, update=True)


def test_highwater_invalid_server_id(tmp_path):
    st = tmp_path / "state"
    with pytest.raises(signing.SigningError):
        signing.check_highwater(st, "0" * 32, "bad/id", 1, update=True)


def test_highwater_mark_unchanged_after_rejected_rollback(tmp_path):
    st = tmp_path / "state"
    signing.check_highwater(st, "0" * 32, "fetch", 3, update=True)
    with pytest.raises(signing.SigningError):
        signing.check_highwater(st, "0" * 32, "fetch", 2, update=True)
    import json
    marks = json.loads((st / signing.HIGHWATER_FILE).read_text())
    assert marks["0" * 32 + "/fetch"] == 3


def test_highwater_corrupt_mark_value(tmp_path):
    import json
    st = tmp_path / "state"
    signing.check_highwater(st, "0" * 32, "fetch", 1, update=True)
    hw_file = st / signing.HIGHWATER_FILE
    corrupt_data = json.dumps({"0" * 32 + "/fetch": True})
    assert json.loads(corrupt_data) is not None  # verify valid JSON
    hw_file.write_text(corrupt_data)
    with pytest.raises(signing.SigningError, match="corrupt"):
        signing.check_highwater(st, "0" * 32, "fetch", 2, update=True)


def test_trust_revoke_wrong_passphrase(cfg):
    k, pub = other_key()
    fp = signing.trust_add(PW, cfg, pub, NOW)
    with pytest.raises(signing.SigningError):
        signing.trust_revoke(b"wrong", cfg, fp, NOW)


def test_trust_revoke_unknown_fingerprint(cfg):
    with pytest.raises(signing.SigningError, match="no trusted key"):
        signing.trust_revoke(PW, cfg, "0" * 64, NOW)


def test_trust_revoke_owner_key(cfg):
    owner_fp = signing.load_own_public(cfg).fingerprint
    with pytest.raises(signing.SigningError, match="cannot revoke the owner key"):
        signing.trust_revoke(PW, cfg, owner_fp, NOW)


def test_trust_revoke_invalid_after(cfg):
    k, pub = other_key()
    fp = signing.trust_add(PW, cfg, pub, NOW)
    with pytest.raises(signing.SigningError):
        signing.trust_revoke(PW, cfg, fp, "not a time")


def test_trust_revoke_move_later_rejected(cfg):
    k, pub = other_key()
    fp = signing.trust_add(PW, cfg, pub, NOW)
    signing.trust_revoke(PW, cfg, fp, "2026-10-10T12:00:00Z")
    with pytest.raises(signing.SigningError, match="revocation can only move earlier"):
        signing.trust_revoke(PW, cfg, fp, "2026-10-11T00:00:00Z")


def test_trust_revoke_move_earlier_succeeds(cfg):
    k, pub = other_key()
    fp = signing.trust_add(PW, cfg, pub, NOW)
    signing.trust_revoke(PW, cfg, fp, "2026-10-10T12:00:00Z")
    signing.trust_revoke(PW, cfg, fp, "2026-10-10T11:00:00Z")
    trusted = signing.load_trusted(cfg)
    assert trusted[fp].revoked_after == parse_time("2026-10-10T11:00:00Z")


def test_trust_revoke_timezone_aware_comparison(cfg):
    import json
    k, pub = other_key()
    fp = signing.trust_add(PW, cfg, pub, NOW)
    signing.trust_revoke(PW, cfg, fp, "2026-10-10T12:00:00Z")
    with pytest.raises(signing.SigningError, match="revocation can only move earlier"):
        signing.trust_revoke(PW, cfg, fp, "2026-10-10T02:00:00-12:00")
    signing.trust_revoke(PW, cfg, fp, "2026-10-10T13:00:00+02:00")
    manifest = json.loads((cfg / signing.MANIFEST_FILE).read_text())
    revoked_key = [k for k in manifest["keys"] if k["fingerprint"] == fp][0]
    assert revoked_key["revokedAfter"] == "2026-10-10T11:00:00Z"


def test_revocation_exact_boundary_rejected(cfg):
    k, pub = other_key()
    fp = signing.trust_add(PW, cfg, pub, NOW)
    revoke_time = "2026-10-10T18:00:00Z"
    signing.trust_revoke(PW, cfg, fp, revoke_time)
    env = envelope(issuedAt=revoke_time)
    with pytest.raises(signing.SigningError, match="revoked"):
        signing.verify_envelope(env, signing.sign_envelope(k, env), signing.load_trusted(cfg), parse_time(revoke_time))


def test_revocation_one_second_before_boundary_verifies(cfg):
    k, pub = other_key()
    fp = signing.trust_add(PW, cfg, pub, NOW)
    revoke_time = "2026-10-10T18:00:00Z"
    signing.trust_revoke(PW, cfg, fp, revoke_time)
    before_revoke = "2026-10-10T17:59:59Z"
    env = envelope(issuedAt=before_revoke)
    result = signing.verify_envelope(env, signing.sign_envelope(k, env), signing.load_trusted(cfg), parse_time(before_revoke))
    assert result == fp


def test_trust_add_non_string_pub(cfg):
    with pytest.raises(signing.SigningError):
        signing.trust_add(PW, cfg, 123, NOW)


def test_trust_add_invalid_now(cfg):
    k, pub = other_key()
    with pytest.raises(signing.SigningError):
        signing.trust_add(PW, cfg, pub, "not a time")


def test_trust_add_revoked_key_rejected(cfg):
    k, pub = other_key()
    fp = signing.trust_add(PW, cfg, pub, NOW)
    signing.trust_revoke(PW, cfg, fp, "2026-10-10T12:00:00Z")
    with pytest.raises(signing.SigningError, match="key is revoked"):
        signing.trust_add(PW, cfg, pub, NOW)


def test_trust_add_idempotent_returns_same_fp(cfg):
    import json
    k, pub = other_key()
    fp1 = signing.trust_add(PW, cfg, pub, NOW)
    fp2 = signing.trust_add(PW, cfg, pub, "2026-10-11T00:00:00Z")
    assert fp1 == fp2
    manifest = json.loads((cfg / signing.MANIFEST_FILE).read_text())
    matching_keys = [k for k in manifest["keys"] if k["fingerprint"] == fp1]
    assert len(matching_keys) == 1


def test_atomic_write_mode_respected(tmp_path):
    p = tmp_path / "test.txt"
    signing._atomic_write(p, b"content")
    assert (os.stat(p).st_mode & 0o777) == 0o600
    p2 = tmp_path / "test2.txt"
    signing._atomic_write(p2, b"content", mode=0o644)
    assert (os.stat(p2).st_mode & 0o777) == 0o644


# --- Final review B2, B4 ---


def test_verify_envelope_uncanonicalizable_is_signing_error(cfg):
    key = signing.load_private(PW, cfg)
    env = envelope()
    sig = signing.sign_envelope(key, env)
    env["entry"]["counter"] = 2**60
    with pytest.raises(signing.SigningError):
        signing.verify_envelope(env, sig, signing.load_trusted(cfg), parse_time(NOW))


def test_verify_envelope_naive_now_is_signing_error(cfg):
    key = signing.load_private(PW, cfg)
    env = envelope()
    sig = signing.sign_envelope(key, env)
    with pytest.raises(signing.SigningError, match="time zone"):
        signing.verify_envelope(env, sig, signing.load_trusted(cfg), parse_time(NOW).replace(tzinfo=None))


def test_highwater_invalid_utf8_is_corrupt(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    p = state / signing.HIGHWATER_FILE
    p.write_bytes(b'{"\xff\xfe": 1}')
    os.chmod(p, 0o600)
    with pytest.raises(signing.SigningError, match="corrupt"):
        signing.check_highwater(state, "0" * 32, "fetch", 1, update=False)


def test_write_private_file_short_write_is_signing_error(tmp_path, monkeypatch):
    monkeypatch.setattr(signing.os, "write", lambda fd, data: 1)
    with pytest.raises(signing.SigningError, match="short write"):
        signing._write_private_file(tmp_path / "k", b"abcdef")


def test_atomic_write_short_write_leaves_target_untouched(tmp_path, monkeypatch):
    target = tmp_path / "f"
    target.write_bytes(b"old")
    monkeypatch.setattr(signing.os, "write", lambda fd, data: 1)
    with pytest.raises(OSError):
        signing._atomic_write(target, b"new contents")
    monkeypatch.undo()
    assert target.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f"]


# --- Final review F1 ---


@pytest.mark.parametrize("flag", ["allowObserve", "allowSampling"])
def test_permissive_entry_far_not_after_verifies(cfg, flag):
    # The 24-hour cap is gone (owner decision 2026-10-05): an owner-set
    # notAfter has no maximum, at 25 hours or ten years past issuedAt.
    key = signing.load_private(PW, cfg)
    entry = {"allowObserve": False, "allowSampling": False, flag: True}
    for not_after in ("2026-10-11T19:00:00Z", "2036-10-10T18:00:00Z"):
        env = envelope(notAfter=not_after, entry=entry)
        signing.verify_envelope(env, signing.sign_envelope(key, env), signing.load_trusted(cfg),
                                parse_time(NOW) + timedelta(hours=24, seconds=1))