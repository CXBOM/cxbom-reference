"""Ed25519 signing for cxbom.lock envelopes and the user's trust manifest.

Owner: ATACE Working Group.

The signature covers the whole envelope, including serverId, lockScope and
entrySeq, so an entry can't be replayed into another server, project or older
state (premortem C3). The key ID is derived from whichever trusted key
verifies. It is never read from the file. The trust manifest is signed by the
user's own key, so dropping a .pub file into the config directory does not
extend trust (C2). Passphrases come only from /dev/tty (C11).
"""
from __future__ import annotations

import base64
import binascii
import errno
import fcntl
import hashlib
import json
import os
import re
import tempfile
import termios
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                               Ed25519PublicKey)

from .canonical import CanonicalizationError, canonical
from .paths import check_private, ensure_private_dir
from .timeutil import parse_time

KEY_FILE = "signing-key.pem"
PUB_FILE = "signing-key.pub"
MANIFEST_FILE = "trusted.json"
HIGHWATER_FILE = "highwater.json"


class SigningError(RuntimeError):
    """A key, signature, manifest, or envelope failed verification."""


@dataclass(frozen=True)
class PublicKey:
    fingerprint: str
    raw: bytes

    def verify(self, sig: bytes, msg: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.raw).verify(sig, msg)
            return True
        except InvalidSignature:
            return False


@dataclass(frozen=True)
class TrustedKey:
    pub: PublicKey
    revoked_after: datetime | None


def fingerprint(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def encode_pub(raw: bytes) -> str:
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def decode_pub(s: str) -> bytes:
    if not s.startswith("ed25519:"):
        raise SigningError("public key must start with 'ed25519:'")
    try:
        raw = base64.b64decode(s[len("ed25519:"):], validate=True)
    except (ValueError, binascii.Error):
        raise SigningError("public key is not valid base64") from None
    if len(raw) != 32:
        raise SigningError("Ed25519 public key must be 32 bytes")
    return raw


def _write_private_file(path: Path, data: bytes) -> None:
    """Create path at 0600 and write data in full.

    Raises:
        SigningError: the file exists, cannot be written, or the write was
            short. The message names only the file.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            n = os.write(fd, data)
            if n != len(data):
                # Remove the truncated key so the next keygen is not refused as existing.
                os.close(fd)
                fd = -1
                os.remove(path)
                raise SigningError(f"{path.name}: short write ({n} of {len(data)} bytes)")
            os.fsync(fd)
        finally:
            if fd >= 0:
                os.close(fd)
    except OSError as e:
        raise SigningError(f"{path.name}: {e.strerror}") from None


def _atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    """Write data to a unique temp file beside path, fsync, then rename over path.

    Raises:
        OSError: any step failed, including a short write. The temp file is
            removed and path is left as it was. Callers wrap this in their
            own error type with only the file name.
    """
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        try:
            if mode is not None:
                os.fchmod(fd, mode)
            n = os.write(fd, data)
            if n != len(data):
                # A short write renamed into place would replace a good file
                # with a truncated one.
                raise OSError(errno.EIO, f"short write ({n} of {len(data)} bytes)")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        raise


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as e:
        raise SigningError(f"{path.name}: {e.strerror}") from None


def _read_text(path: Path) -> str:
    try:
        return _read_bytes(path).decode("utf-8")
    except UnicodeDecodeError:
        raise SigningError(f"{path.name}: not valid UTF-8") from None


def read_passphrase(prompt: str) -> bytes:
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    except OSError:
        raise SigningError("no controlling terminal. cxbom reads passphrases only from /dev/tty") from None
    try:
        old = termios.tcgetattr(fd)
        try:
            new = termios.tcgetattr(fd)
            new[3] &= ~termios.ECHO
            termios.tcsetattr(fd, termios.TCSAFLUSH, new)
            os.write(fd, prompt.encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = os.read(fd, 1)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 1024:
                    raise SigningError("passphrase is too long")
            os.write(fd, b"\n")
            return buf.rstrip(b"\r\n")
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)
    except termios.error:
        raise SigningError("terminal control failed") from None
    finally:
        os.close(fd)


def sign_obj(private_key: Ed25519PrivateKey, obj) -> str:
    return base64.b64encode(private_key.sign(canonical(obj))).decode("ascii")


def verify_obj(pub: PublicKey, obj, sig_b64: str) -> bool:
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (ValueError, binascii.Error):
        return False
    if len(sig) != 64 or base64.b64encode(sig).decode("ascii") != sig_b64:
        return False
    try:
        msg = canonical(obj)
    except CanonicalizationError as e:
        # An object outside the I-JSON domain was never signed by cxbom, and
        # a foreign error type here would escape callers that catch SigningError.
        raise SigningError(f"signed object cannot be canonicalized: {e}") from None
    return pub.verify(sig, msg)


def load_own_public(directory: Path) -> PublicKey:
    path = directory / PUB_FILE
    check_private(path)
    raw = decode_pub(_read_text(path).strip())
    return PublicKey(fingerprint(raw), raw)


def load_private(passphrase: bytes, directory: Path) -> Ed25519PrivateKey:
    check_private(directory)
    path = directory / KEY_FILE
    check_private(path)
    try:
        key = serialization.load_pem_private_key(_read_bytes(path), password=passphrase)
    except (ValueError, TypeError):
        raise SigningError("could not decrypt the signing key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("signing key is not Ed25519")
    return key


def generate_key(passphrase: bytes, directory: Path, now: str) -> str:
    if not passphrase:
        raise SigningError("a passphrase is required")
    ensure_private_dir(directory)
    if (directory / KEY_FILE).exists():
        raise SigningError("a signing key already exists")
    if (directory / PUB_FILE).exists():
        raise SigningError("a signing key already exists")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(passphrase))
    _write_private_file(directory / KEY_FILE, pem)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _write_private_file(directory / PUB_FILE, (encode_pub(raw) + "\n").encode())
    fp = fingerprint(raw)
    manifest = {"contract": {"name": "cxbom-trust", "version": "1.0.0"}, "owner": fp,
                "keys": [{"fingerprint": fp, "publicKey": encode_pub(raw), "addedAt": now,
                          "revokedAfter": None}]}
    _write_manifest(key, directory, manifest)
    return fp


def _write_manifest(private_key: Ed25519PrivateKey, directory: Path, manifest: dict) -> None:
    body = {k: v for k, v in manifest.items() if k != "signature"}
    signed = dict(body, signature=sign_obj(private_key, body))
    try:
        _atomic_write(directory / MANIFEST_FILE, (json.dumps(signed, indent=2, sort_keys=True) + "\n").encode())
    except OSError as e:
        raise SigningError(f"{MANIFEST_FILE}: {e.strerror}") from None


def load_trusted(directory: Path) -> dict[str, TrustedKey]:
    check_private(directory)
    mpath = directory / MANIFEST_FILE
    check_private(mpath)
    try:
        manifest = json.loads(_read_text(mpath))
    except json.JSONDecodeError:
        raise SigningError("trust manifest is not valid JSON") from None
    owner = load_own_public(directory)
    if manifest.get("owner") != owner.fingerprint:
        raise SigningError("trust manifest owner is not this user's key")
    if "keys" not in manifest or not isinstance(manifest["keys"], list):
        raise SigningError("trust manifest is missing or malformed keys list")
    body = {k: v for k, v in manifest.items() if k != "signature"}
    if not verify_obj(owner, body, manifest.get("signature", "")):
        raise SigningError("trust manifest signature is invalid")
    out: dict[str, TrustedKey] = {}
    for k in manifest["keys"]:
        if not isinstance(k, dict):
            raise SigningError("trust manifest key entry is not a dict")
        if "publicKey" not in k or "fingerprint" not in k:
            raise SigningError("trust manifest key entry is missing required fields")
        raw = decode_pub(k["publicKey"])
        if fingerprint(raw) != k["fingerprint"]:
            raise SigningError("trust manifest fingerprint does not match its key")
        try:
            revoked = parse_time(k["revokedAfter"]) if k.get("revokedAfter") else None
        except Exception:
            raise SigningError("trust manifest has unparseable revokedAfter") from None
        out[k["fingerprint"]] = TrustedKey(PublicKey(k["fingerprint"], raw), revoked)
    return out


def sign_envelope(private_key: Ed25519PrivateKey, envelope: dict) -> dict:
    return {"alg": "ed25519", "sig": sign_obj(private_key, envelope)}


def verify_envelope(envelope: dict, signature: dict, trusted: dict[str, TrustedKey],
                    now: datetime) -> str:
    """Return the fingerprint of the trusted key that signed envelope.

    Raises:
        SigningError: now has no time zone, the envelope or signature is
            malformed or uncanonicalizable, no trusted unrevoked key verifies
            it, or its time window is invalid or expired.
    """
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise SigningError("now must be a datetime with a time zone")
    if not isinstance(signature, dict):
        raise SigningError("signature is not a dict")
    if signature.get("alg") != "ed25519":
        raise SigningError("unsupported signature algorithm")
    if "sig" not in signature or not isinstance(signature.get("sig"), str):
        raise SigningError("signature is missing or malformed sig field")
    if not isinstance(envelope, dict):
        raise SigningError("envelope is not a dict")
    if "issuedAt" not in envelope:
        raise SigningError("envelope is missing issuedAt")
    try:
        issued = parse_time(envelope["issuedAt"])
    except Exception:
        raise SigningError("envelope has unparseable issuedAt") from None
    if issued > now + timedelta(seconds=300):
        raise SigningError("entry issuedAt is in the future")
    not_after = envelope.get("notAfter")
    if not_after is not None:
        try:
            not_after_dt = parse_time(not_after)
        except Exception:
            raise SigningError("envelope has unparseable notAfter") from None
        if not_after_dt < issued:
            raise SigningError("entry notAfter is before issuedAt")
    entry = envelope.get("entry")
    if entry is not None and not isinstance(entry, dict):
        raise SigningError("envelope entry is not a dict")
    signer = None
    for fp, tk in trusted.items():
        if verify_obj(tk.pub, envelope, signature.get("sig", "")):
            if tk.revoked_after is not None and issued >= tk.revoked_after:
                raise SigningError(f"signing key {fp[:16]} was revoked before this entry was issued")
            signer = fp
            break
    if signer is None:
        raise SigningError("no trusted key verifies this entry")
    # No tool-set lifetime on any entry, observe and sampling included (owner
    # decision 2026-10-05): the old 24-hour cap made a recording-day lock
    # stop working on its own. A notAfter the owner signed still ends the
    # entry when it passes. The cap's backdating mitigation is given up, and
    # the spec's stated-limits table says so.
    if not_after and now > parse_time(not_after):
        raise SigningError("entry has expired")
    return signer


def _read_manifest(directory: Path) -> dict:
    load_trusted(directory)  # verifies before any change
    return json.loads(_read_text(directory / MANIFEST_FILE))


def trust_add(passphrase: bytes, directory: Path, pub_text: str, now: str) -> str:
    if not isinstance(pub_text, str):
        raise SigningError("public key text must be a string")
    try:
        parse_time(now)
    except Exception:
        raise SigningError("now is not a valid RFC 3339 timestamp") from None
    key = load_private(passphrase, directory)
    manifest = _read_manifest(directory)
    raw = decode_pub(pub_text.strip())
    fp = fingerprint(raw)
    for k in manifest["keys"]:
        if k["fingerprint"] == fp:
            if k["revokedAfter"] is not None:
                raise SigningError("key is revoked. It cannot be re-added")
            return fp
    manifest["keys"].append({"fingerprint": fp, "publicKey": encode_pub(raw), "addedAt": now,
                             "revokedAfter": None})
    _write_manifest(key, directory, manifest)
    return fp


def trust_revoke(passphrase: bytes, directory: Path, fp: str, after: str) -> None:
    key = load_private(passphrase, directory)
    manifest = _read_manifest(directory)
    if fp == manifest["owner"]:
        raise SigningError("cannot revoke the owner key. Rotate to a new key instead")
    try:
        after_dt = parse_time(after)
    except Exception:
        raise SigningError("after is not a valid RFC 3339 timestamp") from None
    for k in manifest["keys"]:
        if k["fingerprint"] == fp:
            existing = k.get("revokedAfter")
            if existing is not None and after_dt > parse_time(existing):
                raise SigningError("revocation can only move earlier")
            k["revokedAfter"] = after_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            _write_manifest(key, directory, manifest)
            return
    raise SigningError(f"no trusted key with fingerprint {fp[:16]}")


def check_highwater(state: Path, scope: str, server_id: str, seq: int, update: bool) -> None:
    if not re.fullmatch(r"[0-9a-f]{32}", scope):
        raise SigningError("scope must be 32 lowercase hex characters")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", server_id):
        raise SigningError("server_id must be 1-64 alphanumeric characters, hyphens, underscores, or dots, starting with alphanumeric")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SigningError("seq must be an integer, not a bool")
    ensure_private_dir(state)
    lock_name = HIGHWATER_FILE + ".lock"
    try:
        lock_fd = os.open(state / lock_name, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        raise SigningError(f"{lock_name}: {e.strerror}") from None
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        path = state / HIGHWATER_FILE
        marks = {}
        if path.exists():
            from .paths import PathSecurityError
            try:
                check_private(path)
            except PathSecurityError:
                raise SigningError("high-water file is corrupt") from None
            try:
                marks_data = json.loads(path.read_text())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                raise SigningError("high-water file is corrupt") from None
            if not isinstance(marks_data, dict):
                raise SigningError("high-water file is corrupt")
            for mark_key, mark_val in marks_data.items():
                if not isinstance(mark_val, int) or isinstance(mark_val, bool):
                    raise SigningError("high-water file is corrupt")
            marks = marks_data
        key = f"{scope}/{server_id}"
        prev = marks.get(key)
        if prev is not None and seq < prev:
            raise SigningError(f"entry {server_id} seq {seq} is older than accepted seq {prev}; rollback refused")
        if update and (prev is None or seq > prev):
            marks[key] = seq
            try:
                _atomic_write(path, (json.dumps(marks, indent=2, sort_keys=True) + "\n").encode())
            except OSError as e:
                raise SigningError(f"{HIGHWATER_FILE}: {e.strerror}") from None
    finally:
        os.close(lock_fd)
