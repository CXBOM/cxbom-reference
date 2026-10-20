"""Family marker tables pinned by chat_template hash (spec 9.2). Owner: ATACE Working Group."""
import dataclasses
from pathlib import Path
from types import MappingProxyType

import pytest

from cxbom import templates
from cxbom.tokenizer import load_tokenizer

FIX = Path(__file__).resolve().parent / "fixtures" / "phi3"
TOK_SHA = "9e2ae3d66819f163cdcfedba5078f3a3af8118c2712491ed60912f77886bda6f"


@pytest.fixture(scope="module")
def tok():
    return load_tokenizer(FIX / "tokenizer.json", config=FIX / "tokenizer_config.json", expected_sha256=TOK_SHA)


def test_phi3_table_matches_the_pinned_tokenizer(tok):
    table = templates.table_for("phi3", tok)
    assert table.roles == frozenset({"system", "user", "assistant"})
    assert {r: m.ids for r, m in table.markers.items()} == {
        "system": (32006,), "user": (32010,), "assistant": (32001,), "end": (32007,)}
    assert all(m.text.endswith("\n") for m in table.markers.values())


def test_template_hash_mismatch_raises(tok):
    other = dataclasses.replace(tok, chat_template_sha256="0" * 64)
    with pytest.raises(templates.TemplateError, match="chat_template sha256"):
        templates.table_for("phi3", other)


def test_unknown_family_raises(tok):
    with pytest.raises(templates.TemplateError, match="unknown template family 'no-such-family'"):
        templates.table_for("no-such-family", tok)


def test_marker_id_drift_raises(tok):
    bad = dataclasses.replace(templates.PHI3, markers=MappingProxyType(
        dict(templates.PHI3.markers, user=templates.Marker("<|user|>\n", (32010, 13)))))
    with pytest.raises(templates.TemplateError, match="'user' encodes to"):
        templates.verify(bad, tok)
