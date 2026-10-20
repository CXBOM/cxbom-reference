"""Content-addressed store (spec 5). Owner: ATACE Working Group."""
import os

import pytest

from cxbom.store import Store, StoreError


def test_round_trip_and_permissions(tmp_path):
    s = Store(tmp_path / "store")
    h = s.put_json({"b": 1, "a": "x"})
    assert s.get_json(h) == {"a": "x", "b": 1}
    t = s.put_text("hello\n")
    assert s.get_text(t) == "hello\n"
    # Verify all files are 0600
    for p in (tmp_path / "store").rglob("*"):
        if p.is_file():
            assert (os.stat(p).st_mode & 0o777) == 0o600
    # Verify all directories (including root) are 0700
    for p in [tmp_path / "store", *(tmp_path / "store").rglob("*")]:
        if p.is_dir():
            assert (os.stat(p).st_mode & 0o777) == 0o700


def test_tampered_object_detected(tmp_path):
    s = Store(tmp_path / "store")
    h = s.put_text("original")
    (tmp_path / "store" / "text" / f"{h}.txt").write_text("changed")
    with pytest.raises(StoreError):
        s.get_text(h)


def test_missing(tmp_path):
    with pytest.raises(StoreError):
        Store(tmp_path / "store").get_json("0" * 64)


def test_invalid_hash_strings(tmp_path):
    """Invalid hash strings should raise StoreError with correct message."""
    s = Store(tmp_path / "store")
    # "../etc" is not valid hex
    with pytest.raises(StoreError, match="invalid store hash"):
        s.get_json("../etc")
    # "ABC" is not lowercase hex and not 64 chars
    with pytest.raises(StoreError, match="invalid store hash"):
        s.get_json("ABC")
    # "0" * 63 is only 63 chars, needs 64
    with pytest.raises(StoreError, match="invalid store hash"):
        s.get_json("0" * 63)
    # Same for get_text
    with pytest.raises(StoreError, match="invalid store hash"):
        s.get_text("../etc")
    with pytest.raises(StoreError, match="invalid store hash"):
        s.get_text("ABC")
    with pytest.raises(StoreError, match="invalid store hash"):
        s.get_text("0" * 63)


def test_non_str_sha_raises_error(tmp_path):
    """Non-string sha values should raise StoreError."""
    s = Store(tmp_path / "store")
    with pytest.raises(StoreError, match="invalid store hash"):
        s.get_json(None)
    with pytest.raises(StoreError, match="invalid store hash"):
        s.get_json(5)
    with pytest.raises(StoreError, match="invalid store hash"):
        s.get_text(None)
    with pytest.raises(StoreError, match="invalid store hash"):
        s.get_text(5)


def test_def_file_overwritten_with_invalid_json(tmp_path):
    """A def file overwritten with invalid JSON should raise StoreError."""
    s = Store(tmp_path / "store")
    h = s.put_json({"valid": "data"})
    # Overwrite the file with invalid JSON
    (tmp_path / "store" / "defs" / f"{h}.json").write_bytes(b"{invalid json")
    with pytest.raises(StoreError):
        s.get_json(h)


def test_def_file_with_nan(tmp_path):
    """A def file containing NaN should raise StoreError (not valid JSON per spec)."""
    s = Store(tmp_path / "store")
    h = s.put_json({"valid": "data"})
    # Overwrite with NaN
    (tmp_path / "store" / "defs" / f"{h}.json").write_bytes(b'{"a": NaN}')
    with pytest.raises(StoreError):
        s.get_json(h)


def test_text_file_overwritten_with_invalid_utf8(tmp_path):
    """A text file overwritten with invalid UTF-8 should raise StoreError."""
    s = Store(tmp_path / "store")
    h = s.put_text("original text")
    # Overwrite with invalid UTF-8
    (tmp_path / "store" / "text" / f"{h}.txt").write_bytes(b"\xff\xfe")
    with pytest.raises(StoreError):
        s.get_text(h)


def test_tampering_repaired_by_reput(tmp_path):
    """Putting the same text after tampering repairs it."""
    s = Store(tmp_path / "store")
    original = "repair me"
    h = s.put_text(original)
    # Tamper with the file
    (tmp_path / "store" / "text" / f"{h}.txt").write_text("tampered")
    # Verify tampering is detected
    with pytest.raises(StoreError):
        s.get_text(h)
    # Re-put the same text (which is idempotent since _write uses atomic_write)
    h2 = s.put_text(original)
    assert h2 == h
    # Now the file should be valid again
    assert s.get_text(h) == original


def test_no_stray_temp_files_remain(tmp_path):
    """No stray temp files should remain after puts. Only expected files present."""
    s = Store(tmp_path / "store")
    h1 = s.put_json({"test": "data"})
    h2 = s.put_text("test content")
    # Check defs directory contains exactly {h1}.json
    defs_dir = tmp_path / "store" / "defs"
    defs_files = {p.name for p in defs_dir.glob("*") if p.is_file()}
    assert defs_files == {f"{h1}.json"}
    # Check text directory contains exactly {h2}.txt
    text_dir = tmp_path / "store" / "text"
    text_files = {p.name for p in text_dir.glob("*") if p.is_file()}
    assert text_files == {f"{h2}.txt"}


# --- Final review B4: store failures are StoreError ---


@pytest.mark.parametrize("bad", [{"x": float("nan")}, {"x": 2**60}])
def test_put_json_uncanonicalizable_is_store_error(tmp_path, bad):
    with pytest.raises(StoreError):
        Store(tmp_path / "store").put_json(bad)


def test_put_write_oserror_is_store_error(tmp_path):
    s = Store(tmp_path / "store")
    os.chmod(tmp_path / "store" / "text", 0o500)
    try:
        with pytest.raises(StoreError):
            s.put_text("hello")
    finally:
        os.chmod(tmp_path / "store" / "text", 0o700)


# --- Final review F3 ---


def test_def_file_replaced_with_other_valid_canonical_json(tmp_path):
    s = Store(tmp_path / "store")
    h = s.put_json({"name": "fetch", "description": "approved"})
    (tmp_path / "store" / "defs" / f"{h}.json").write_bytes(b'{"description":"poisoned","name":"fetch"}')
    with pytest.raises(StoreError, match="does not match"):
        s.get_json(h)
