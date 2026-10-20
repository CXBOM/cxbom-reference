"""The context strip and ledger show the reference record's real numbers.

Owner: ATACE Working Group.
"""
import copy
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "site"))
from cxsite import strip  # noqa: E402

RECORD = json.loads((ROOT / "site/data/session_reference.json").read_text(encoding="utf-8"))


def test_segments_are_the_rings_then_overhead():
    assert [(s.key, s.tokens) for s in strip.segments(RECORD)] == [("0", 45), ("1", 46131), ("2", 16), ("o", 13)]


def test_widths_are_true_proportions_of_46205():
    svg = strip.strip_svg(RECORD, "s")
    widths = [float(w) for w in re.findall(r'<rect x="[0-9.]+" y="8" width="([0-9.]+)"', svg)]
    assert widths == pytest.approx([1000 * t / 46205 for t in (45, 46131, 16, 13)], abs=0.001)
    assert sum(widths) == pytest.approx(1000, abs=0.01)


def test_svg_is_an_accessible_image_that_states_the_counts_in_words():
    svg = strip.strip_svg(RECORD, "s")
    assert 'role="img" aria-labelledby="s-t s-d"' in svg
    assert '<title id="s-t">' in svg
    desc = re.search(r'<desc id="s-d">(.*?)</desc>', svg).group(1)
    assert desc == ("Reference session context window use: 46,205 tokens. "
                    "Ring 0 (operator): 45 tokens, solid. Ring 1 (agent): 46,131 tokens, hatched. "
                    "Ring 2 (user): 16 tokens, dotted. Template overhead: 13 tokens, lined.")


def test_each_ring_has_its_own_pattern_and_ids_are_prefixed():
    svg = strip.strip_svg(RECORD, "zz")
    assert 'class="f0"' in svg
    for k in ("1", "2", "o"):
        assert f'<pattern id="zz-p{k}"' in svg and f'fill="url(#zz-p{k})"' in svg


def test_strip_refuses_a_record_that_does_not_reconcile():
    bad = copy.deepcopy(RECORD)
    bad["sessionSummary"]["componentBreakdown"]["byTrustRing"]["ring0"]["tokens"] = 46
    with pytest.raises(strip.StripError, match="totalContextTokens"):
        strip.segments(bad)
    bad = copy.deepcopy(RECORD)
    bad["metadata"]["session"]["contextWindowTokensUsed"] = 46192
    with pytest.raises(strip.StripError, match="contextWindowTokensUsed"):
        strip.segments(bad)


def test_ledger_has_one_row_per_component_and_stamps():
    table = strip.ledger_table(RECORD)
    assert table.count("<tr><td class=\"num\">") == 6
    assert table.count('<span class="stamp">TRUST INVERSION</span>') == 1
    assert table.count('<span class="stamp plain">NOT ASSESSED</span>') == 5
    assert '<th scope="row">cc-002</th>' in table
    assert "<caption>Reference session ledger: 6 components, 46,192 component tokens and 13 template overhead tokens.</caption>" in table
    assert '<td class="num">46,205</td>' in table
    assert 'aria-hidden="true"' in table


def test_strip_note_calls_out_ring_zero():
    assert strip.strip_note(RECORD) == ('<p class="strip-note">Reference session: ring 0 (operator, marked) '
                                        "holds 45 of 46,205 tokens.</p>")
