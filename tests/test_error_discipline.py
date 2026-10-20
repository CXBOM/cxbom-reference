"""Exceptions carry only file names, never absolute paths (anonymity).

Owner: ATACE Working Group.

Every module that touches the filesystem formats an OSError as the file's
base name plus the error text, so an exception a caller logs or a CLI prints
cannot leak the account home or a temporary directory.
"""
import os
import pwd
import shutil

import pytest

from cxbom import attestation, canonical, lockfile, signing
from cxbom.paths import PathSecurityError
from cxbom.store import Store, StoreError

HOME = pwd.getpwuid(os.getuid()).pw_dir


def _lockfile(tmp_path):
    lockfile.read_lock(tmp_path / "missing.lock")


def _attestation(tmp_path):
    attestation.read_log(tmp_path / "missing.jsonl")


def _store(tmp_path):
    s = Store(tmp_path / "store")
    shutil.rmtree(tmp_path / "store" / "defs")
    s.put_json({"a": 1})


def _signing_manifest(tmp_path):
    d = tmp_path / "config"
    signing.generate_key(b"pw", d, "2026-10-10T18:00:00Z")
    (d / signing.MANIFEST_FILE).unlink()
    signing.load_trusted(d)


def _signing_highwater(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / (signing.HIGHWATER_FILE + ".lock")).symlink_to(tmp_path / "missing-target")
    signing.check_highwater(state, "0" * 32, "fetch", 1, update=True)


def _canonical_file(tmp_path):
    canonical.file_sha256(tmp_path / "missing.bin")


def _canonical_tree(tmp_path):
    canonical.tree_sha256(tmp_path / "missing-tree")


CASES = {
    "lockfile": (_lockfile, lockfile.LockError),
    "attestation": (_attestation, attestation.AttestationIOError),
    "store": (_store, StoreError),
    "signing-manifest": (_signing_manifest, (signing.SigningError, PathSecurityError)),
    "signing-highwater": (_signing_highwater, signing.SigningError),
    "canonical-file": (_canonical_file, canonical.CanonicalizationError),
    "canonical-tree": (_canonical_tree, canonical.CanonicalizationError),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_filesystem_errors_carry_no_absolute_path(tmp_path, case):
    trigger, exc_type = CASES[case]
    with pytest.raises(exc_type) as ei:
        trigger(tmp_path)
    msg = str(ei.value)
    assert HOME not in msg
    assert str(tmp_path) not in msg
    assert str(tmp_path.resolve()) not in msg
