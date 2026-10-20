"""RFC 8785 hashing and ignore-pointer rules (spec 5, premortem C6). Owner: ATACE Working Group."""
import os

import pytest

from cxbom import canonical as c

FETCH = {"name": "fetch", "description": "Fetches a URL.", "inputSchema": {"type": "object"},
         "_meta": {"updatedAt": "2026-10-01T00:00:00Z", "rev": 3}}


def test_known_hash_of_atace_fetch_fixture():
    # The vendored fetch definition from ATACE. The value appears in contracts/proxy/example.cxbom.lock v1.
    tool = {"name": "fetch", "description": "Fetches a URL from the internet and extracts its contents as markdown.",
            "inputSchema": {"description": "Parameters for fetching a URL.", "properties": {
                "url": {"description": "URL to fetch", "format": "uri", "minLength": 1, "title": "Url", "type": "string"},
                "max_length": {"default": 5000, "description": "Maximum number of characters to return.",
                               "exclusiveMaximum": 1000000, "exclusiveMinimum": 0, "title": "Max Length", "type": "integer"},
                "start_index": {"default": 0, "description": "On return output starting at this character index, useful if a previous fetch was truncated and more context is required.",
                                "minimum": 0, "title": "Start Index", "type": "integer"},
                "raw": {"default": False, "description": "Get the actual HTML content of the requested page, without simplification.",
                        "title": "Raw", "type": "boolean"}},
                "required": ["url"], "title": "Fetch", "type": "object"}}
    assert c.tool_sha256(tool) == "5aa12876892b083fa01a925df774c715b11a20a3c47164e14b6126e731460dd1"


def test_ignore_pointer_changes_hash_only_for_that_leaf():
    base = c.tool_sha256(FETCH, ["/_meta/updatedAt"])
    moved = dict(FETCH, _meta={"updatedAt": "2026-10-02T00:00:00Z", "rev": 3})
    assert c.tool_sha256(moved, ["/_meta/updatedAt"]) == base
    assert c.tool_sha256(moved) != c.tool_sha256(FETCH)


@pytest.mark.parametrize("ptr", ["/_meta", "/description", "/_meta/", "_meta/x", "/_meta/a/"])
def test_bad_pointers(ptr):
    with pytest.raises(c.IgnoredFieldError):
        c.validate_ignore_pointer(ptr)


@pytest.mark.parametrize("value", [{"note": "do evil"}, "x" * 41, "not a timestamp", ["a"], "2026-99-99T99:99:99Z", 2**60])
def test_ignored_leaf_must_stay_benign(value):
    bad = dict(FETCH, _meta={"updatedAt": value, "rev": 3})
    with pytest.raises(c.IgnoredFieldError):
        c.tool_sha256(bad, ["/_meta/updatedAt"])


@pytest.mark.parametrize("bad", [{"n": 2 ** 60}, {"n": float("nan")}, {"s": "\ud800"}])
def test_uncanonicalizable(bad):
    with pytest.raises(c.CanonicalizationError):
        c.object_sha256(bad)


def test_instructions_hash_is_of_json_string():
    assert c.instructions_sha256("") == c.sha256_hex(b'""')


def test_tree_hash_and_symlink_refusal(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    h1 = c.tree_sha256(tmp_path)
    (tmp_path / "pkg" / "a.py").write_text("x = 2\n")
    assert c.tree_sha256(tmp_path) != h1
    os.symlink(tmp_path / "b.py", tmp_path / "link.py")
    with pytest.raises(c.CanonicalizationError):
        c.tree_sha256(tmp_path)


def test_small_numbers_ok_at_ignored_pointer():
    good_int = dict(FETCH, _meta={"updatedAt": 3, "rev": 3})
    assert c.tool_sha256(good_int, ["/_meta/updatedAt"]) is not None
    good_float = dict(FETCH, _meta={"updatedAt": 1.5, "rev": 3})
    assert c.tool_sha256(good_float, ["/_meta/updatedAt"]) is not None


def test_symlinked_tree_root_raises(tmp_path):
    (tmp_path / "real_dir").mkdir()
    (tmp_path / "real_dir" / "f.txt").write_text("content\n")
    symlink_root = tmp_path / "symlink_dir"
    os.symlink(tmp_path / "real_dir", symlink_root)
    with pytest.raises(c.CanonicalizationError):
        c.tree_sha256(symlink_root)


# --- Final review B4: filesystem failures are CanonicalizationError ---


def test_file_sha256_missing_and_unreadable(tmp_path):
    with pytest.raises(c.CanonicalizationError):
        c.file_sha256(tmp_path / "missing")
    f = tmp_path / "secret"
    f.write_bytes(b"x")
    os.chmod(f, 0)
    try:
        with pytest.raises(c.CanonicalizationError):
            c.file_sha256(f)
    finally:
        os.chmod(f, 0o600)


def test_tree_sha256_missing_root(tmp_path):
    with pytest.raises(c.CanonicalizationError):
        c.tree_sha256(tmp_path / "missing")


def test_tree_sha256_unreadable_subdirectory_is_never_skipped(tmp_path):
    root = tmp_path / "t"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "f").write_text("x")
    (root / "top").write_text("y")
    os.chmod(root / "sub", 0)
    try:
        with pytest.raises(c.CanonicalizationError):
            c.tree_sha256(root)
    finally:
        os.chmod(root / "sub", 0o700)


@pytest.mark.parametrize("value, ok", [
    ("2026-10-10T18:00:00.5Z", True),
    ("2026-10-10T18:00:00.123456789Z", True),
    ("2026-10-10 18:00:00Z", False),
    ("2026-02-30T00:00:00Z", False),
])
def test_ignored_timestamp_verdict_is_version_independent(value, ok):
    assert c.ignored_value_ok(value) is ok


# --- Final review F4 ---


def test_tree_sha256_refuses_symlinked_subdirectory(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.py").write_text("import os\n")
    (root / "vendor").symlink_to(outside, target_is_directory=True)
    with pytest.raises(c.CanonicalizationError, match="symlink"):
        c.tree_sha256(root)
