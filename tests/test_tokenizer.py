"""Pinned offline tokenizer loading and the two part encoders (spec 9.1).

Owner: ATACE Working Group. Runs offline from the vendored Phi-3.5 fixture.
"""
import hashlib
import json
import random
from pathlib import Path

import pytest

from cxbom.tokenizer import TokenizerError, load_tokenizer

FIX = Path(__file__).resolve().parent / "fixtures" / "phi3"
TOK_SHA = "9e2ae3d66819f163cdcfedba5078f3a3af8118c2712491ed60912f77886bda6f"
TEMPLATE_SHA = "78d976a442bcde2f0be15aafbb8e3050e1104f86732266f68403251b89982a90"


@pytest.fixture(scope="module")
def tok():
    return load_tokenizer(FIX / "tokenizer.json", config=FIX / "tokenizer_config.json", expected_sha256=TOK_SHA)


def test_pins_and_metadata(tok):
    assert tok.sha256 == TOK_SHA
    assert tok.chat_template_sha256 == TEMPLATE_SHA
    assert tok.bos_ids == ()                      # this revision sets add_bos_token false
    assert tok.special_ids["<|system|>"] == 32006
    assert tok.bos_eos == frozenset({"<s>", "<|endoftext|>"})


def test_segment_start_and_continuation_encoders(tok):
    text = "You are a helper."
    assert tok.encode(text, segment_start=True) == [887, 526, 263, 16876, 29889]
    assert tok.encode(text, segment_start=False) == [3492, 526, 263, 16876, 29889]
    assert tok.encode("\n", segment_start=True) == [29871, 13]
    assert tok.encode("\n", segment_start=False) == [13]


def test_marker_absorbs_the_following_newline(tok):
    # Phi-3.5 marks <|system|> rstrip, so the newline in the template has no token.
    for start in (True, False):
        assert tok.encode("<|system|>\n", segment_start=start) == [32006]
        assert tok.encode("<|system|>", segment_start=start) == [32006]


def test_wrong_pin_refused():
    with pytest.raises(TokenizerError, match="does not match the pin"):
        load_tokenizer(FIX / "tokenizer.json", config=FIX / "tokenizer_config.json", expected_sha256="0" * 64)
    with pytest.raises(TokenizerError, match="64 lowercase hex"):
        load_tokenizer(FIX / "tokenizer.json", config=FIX / "tokenizer_config.json", expected_sha256="9E2A")


def test_config_is_parsed_strictly(tmp_path):
    cfg = tmp_path / "tokenizer_config.json"
    cfg.write_text('{"chat_template": "a", "chat_template": "b"}')
    with pytest.raises(TokenizerError, match="strict JSON"):
        load_tokenizer(FIX / "tokenizer.json", config=cfg, expected_sha256=TOK_SHA)
    cfg.write_text('{"add_bos_token": false}')
    with pytest.raises(TokenizerError, match="chat_template"):
        load_tokenizer(FIX / "tokenizer.json", config=cfg, expected_sha256=TOK_SHA)
    with pytest.raises(TokenizerError, match="cannot read"):
        load_tokenizer(FIX / "tokenizer.json", config=tmp_path / "missing.json", expected_sha256=TOK_SHA)


def test_add_bos_token_puts_bos_first(tmp_path):
    cfg = json.loads((FIX / "tokenizer_config.json").read_text(encoding="utf-8"))
    cfg["add_bos_token"] = True
    path = tmp_path / "tokenizer_config.json"
    path.write_text(json.dumps(cfg))
    tok = load_tokenizer(FIX / "tokenizer.json", config=path, expected_sha256=TOK_SHA)
    assert tok.bos_ids == (1,)


def test_unsupported_prefix_shape_fails_closed(tmp_path):
    doc = json.loads((FIX / "tokenizer.json").read_text(encoding="utf-8"))
    doc["pre_tokenizer"] = {"type": "Metaspace", "replacement": "▁", "prepend_scheme": "always", "split": False}
    path = tmp_path / "tokenizer.json"
    path.write_text(json.dumps(doc))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(TokenizerError, match="Metaspace"):
        load_tokenizer(path, config=FIX / "tokenizer_config.json", expected_sha256=sha)


def test_prepend_that_is_not_first_fails_closed(tmp_path):
    doc = json.loads((FIX / "tokenizer.json").read_text(encoding="utf-8"))
    doc["normalizer"]["normalizers"].reverse()
    path = tmp_path / "tokenizer.json"
    path.write_text(json.dumps(doc))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(TokenizerError, match="not first"):
        load_tokenizer(path, config=FIX / "tokenizer_config.json", expected_sha256=sha)


# --- compose() and the marker rstrip mirror (spec 9.1 composability guarantee) ---
#
# Each test below builds a part list with compose() and checks it against
# whole-string encoding of the equivalent concatenated text, because that
# equivalence is the guarantee the assembly (Task 9) depends on.


def test_compose_matches_whole_string_marker_then_leading_space(tok):
    system_id = tok.special_ids["<|system|>"]
    parts = [system_id, " You are a helper."]
    whole = tuple(tok.encode("<|system|> You are a helper.", segment_start=True))
    assert tok.compose(parts) == whole


def test_compose_matches_whole_string_marker_then_leading_newline(tok):
    system_id = tok.special_ids["<|system|>"]
    parts = [system_id, "\nYou are a helper."]
    whole = tuple(tok.encode("<|system|>\nYou are a helper.", segment_start=True))
    assert tok.compose(parts) == whole


def test_compose_matches_whole_string_marker_then_no_gap(tok):
    system_id = tok.special_ids["<|system|>"]
    parts = [system_id, "You are a helper."]
    whole = tuple(tok.encode("<|system|>You are a helper.", segment_start=True))
    assert tok.compose(parts) == whole


def test_compose_empty_leading_part_does_not_flip_the_encoder(tok):
    parts = ["", "Hello world."]
    whole = tuple(tok.encode("Hello world.", segment_start=True))
    assert tok.compose(parts) == whole


def test_compose_empty_middle_part_does_not_flip_the_encoder(tok):
    parts = ["Hello", "", " world."]
    whole = tuple(tok.encode("Hello world.", segment_start=True))
    assert tok.compose(parts) == whole


def test_compose_whitespace_only_middle_part_fails_closed(tok):
    # " " on its own is a real part (it yields the id for "▁"), but that id
    # cannot be reattached to "world." the way whole-string encoding would.
    with pytest.raises(TokenizerError, match="whitespace-only"):
        tok.compose(["Hello", " ", "world."])


def test_compose_matches_whole_string_with_non_ascii_text(tok):
    system_id = tok.special_ids["<|system|>"]
    parts = [system_id, " café résumé"]
    whole = tuple(tok.encode("<|system|> café résumé", segment_start=True))
    assert tok.compose(parts) == whole


def test_compose_matches_whole_string_starting_with_punctuation(tok):
    system_id = tok.special_ids["<|system|>"]
    parts = [system_id, ".Response text."]
    whole = tuple(tok.encode("<|system|>.Response text.", segment_start=True))
    assert tok.compose(parts) == whole


def test_compose_matches_whole_string_for_the_briefs_scaffold_layout(tok):
    system_id = tok.special_ids["<|system|>"]
    end_id = tok.special_ids["<|end|>"]
    parts = [system_id, "\nYou are a helper.", end_id]
    whole = tuple(tok.encode("<|system|>\nYou are a helper.<|end|>", segment_start=True))
    assert tok.compose(parts) == whole


def test_absorbed_count_for_marker_then_newline_and_two_spaces(tok):
    system_id = tok.special_ids["<|system|>"]
    result = tok.encode_part("\n  Hi", prev_id=system_id, segment_start=True)
    assert result.absorbed == 3


def test_lstrip_marker_fails_closed(tmp_path):
    doc = json.loads((FIX / "tokenizer.json").read_text(encoding="utf-8"))
    for entry in doc["added_tokens"]:
        if entry.get("content") == "<|system|>":
            entry["lstrip"] = True
    path = tmp_path / "tokenizer.json"
    path.write_text(json.dumps(doc))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(TokenizerError, match="lstrip"):
        load_tokenizer(path, config=FIX / "tokenizer_config.json", expected_sha256=sha)


# --- compose() never diverges silently (fix round 2) ---


def test_compose_trailing_whitespace_before_text_part_fails_closed(tok):
    with pytest.raises(TokenizerError, match="ends in whitespace before another text part"):
        tok.compose(["Hello ", "café résumé."])


def test_compose_never_silently_diverges_from_whole_string_encoding(tok, capsys):
    """300 random layouts, fixed seed: compose() must match whole-string encoding or raise.

    A silent mismatch is the one outcome this test does not tolerate. The word
    list mixes plain words, spaces, a double space, a newline, punctuation, and
    one non-ASCII word ("café"), interleaved with the four chat-template
    markers at roughly a one-in-three chance per part.
    """
    markers = [tok.special_ids[content] for content in
               ("<|system|>", "<|user|>", "<|assistant|>", "<|end|>")]
    content_by_marker = {v: k for k, v in tok.special_ids.items()}
    words = ["Hello", "world", "You", "are", "a", "helper", "café", " ", "  ", "\n", ".", ",", "text"]
    rng = random.Random(20260925)
    raised = 0
    for _ in range(300):
        length = rng.randint(1, 6)
        parts = [rng.choice(markers) if rng.random() < 0.35 else rng.choice(words) for _ in range(length)]
        try:
            composed = tok.compose(parts)
        except TokenizerError:
            raised += 1
            continue
        whole_text = "".join(p if isinstance(p, str) else content_by_marker[p] for p in parts)
        whole_ids = tuple(tok.encode(whole_text, segment_start=True))
        assert composed == whole_ids, f"silent divergence for {parts!r}"
    with capsys.disabled():
        print(f"\nfuzz: {raised}/300 layouts raised TokenizerError, {300 - raised}/300 matched whole-string ids")
