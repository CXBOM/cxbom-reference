"""Per-family chat marker tables, pinned by the chat_template hash (spec 9.2).

Owner: ATACE Working Group.

Each marker is listed as the exact string the family's chat template writes
and the token ids the pinned tokenizer gives it. The phi3 strings end in a
newline because the template writes '<|system|>\\n'. Phi-3.5 marks its role
tokens rstrip, so the tokenizer absorbs that newline and the whole marker is
one id. Listing the string with its newline and the single id makes that
absorption explicit, and ids mode counts the newline as overhead by
construction (the Jetson STATUS edge case).

The qwen3 markers are role text, not single ids: '<|im_start|>system\n' is
the special token, the plain word, and a newline. Its think_off entry is the
empty '<think>\n\n</think>\n\n' block the Qwen3 template writes after the
assistant marker when thinking is off. That block opens no role region and
closes none, so SCAFFOLD lists it with CLOSE and roles leaves both out. The
qwen3 values are copied from the Jetson's lab/j1/marker_tables.py, and
tests/test_qwen3.py requires the two tables to stay equal.

Qwen3 wraps a tool result in a user turn: the template writes
'<|im_start|>user', then '\\n<tool_response>\\n', the content,
'\\n</tool_response>' and '<|im_end|>\\n'. The table carries the opening role
text and the wrapper open as one marker, because the template writes them with
no newline between them, and the wrapper close as its own scaffold marker so
marker('end') stays the only way to close a region. The template writes the
bare '\\n<tool_response>\\n' open for a second consecutive tool message, with
no role text; this table has no marker for that shape, so Assembly refuses a
second wrapper inside one open region rather than writing a second full wrapper
in its place, which the template never writes there. A second wrapped turn after
marker('end') is a different shape and is allowed: it is what the template
writes for a tool message that does not follow another tool message.

Inside one wrapper Assembly builds the sequence the template writes and refuses
every other one: the open marker, exactly one tool_result component, the close
marker, marker('end'). Nothing else goes between the two wrapper markers and
nothing goes after the close, because the template writes nothing there. See
Assembly._wrapper_admits, which is that sentence as code.

A table's inline markers are a second, separate namespace: tags the template
writes inside a turn rather than around one. qwen3 carries two, the
'<tool_call>' and '</tool_call>' tags its template writes in the system
prompt's tool instructions. Assembly.inline_marker appends one as overhead and
marker() cannot reach them, so no inline tag can open or close a region. Each
must be one added token whose added_tokens content is the tag itself and that
absorbs no whitespace, which is what lets it sit between two text parts with no
BPE merge across either boundary. verify() refuses a table that breaks this.

table_for re-encodes every marker with the loaded tokenizer and refuses the
table on any difference, so a tokenizer that drifted under a matching
template hash still fails closed at Assembly construction (spec 13).
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .tokenizer import LoadedTokenizer

CLOSE = "end"
THINK_OFF = "think_off"
TOOL_RESPONSE = "tool_response"
TOOL_RESPONSE_END = "tool_response_end"
TOOL_CALL = "tool_call"
TOOL_CALL_END = "tool_call_end"
# Markers that are pure scaffold: they never open a role region.
SCAFFOLD = frozenset({CLOSE, THINK_OFF, TOOL_RESPONSE_END})
# Markers that add no role or turn marker of their own. Spec 13 ranks a special
# token found in component content 'high' only when it is a chat role or turn
# marker, so the added tokens these markers introduce (<think>, </think>,
# <tool_response>, </tool_response>) rank as other special tokens instead.
# tool_response is listed here even though it opens a region: the role marker it
# writes, <|im_start|>user, is already carried by the plain 'user' marker, and
# the only token this marker adds on top of that is the wrapper tag.
TAG_ONLY = frozenset({THINK_OFF, TOOL_RESPONSE, TOOL_RESPONSE_END})


class TemplateError(ValueError):
    """The family is unknown, its template hash differs, or a marker's ids differ."""


@dataclass(frozen=True)
class Marker:
    text: str
    ids: tuple[int, ...]


@dataclass(frozen=True)
class FamilyTable:
    family: str
    chat_template_sha256: str
    markers: Mapping[str, Marker]
    # Tags written inside a turn, reachable only through Assembly.inline_marker.
    inline: Mapping[str, Marker] = MappingProxyType({})

    @property
    def roles(self) -> frozenset[str]:
        return frozenset(r for r in self.markers if r not in SCAFFOLD)


PHI3 = FamilyTable(
    family="phi3",
    chat_template_sha256="78d976a442bcde2f0be15aafbb8e3050e1104f86732266f68403251b89982a90",
    markers=MappingProxyType({
        "system": Marker("<|system|>\n", (32006,)),
        "user": Marker("<|user|>\n", (32010,)),
        "assistant": Marker("<|assistant|>\n", (32001,)),
        CLOSE: Marker("<|end|>\n", (32007,)),
    }),
)

QWEN3 = FamilyTable(
    family="qwen3",
    chat_template_sha256="a55ee1b1660128b7098723e0abcd92caa0788061051c62d51cbe87d9cf1974d8",
    markers=MappingProxyType({
        "system": Marker("<|im_start|>system\n", (151644, 8948, 198)),
        "user": Marker("<|im_start|>user\n", (151644, 872, 198)),
        "assistant": Marker("<|im_start|>assistant\n", (151644, 77091, 198)),
        CLOSE: Marker("<|im_end|>\n", (151645, 198)),
        THINK_OFF: Marker("<think>\n\n</think>\n\n", (151667, 271, 151668, 271)),
        TOOL_RESPONSE: Marker("<|im_start|>user\n<tool_response>\n", (151644, 872, 198, 151665, 198)),
        TOOL_RESPONSE_END: Marker("\n</tool_response>", (198, 151666)),
    }),
    inline=MappingProxyType({
        TOOL_CALL: Marker("<tool_call>", (151657,)),
        TOOL_CALL_END: Marker("</tool_call>", (151658,)),
    }),
)

FAMILIES: Mapping[str, FamilyTable] = MappingProxyType({"phi3": PHI3, "qwen3": QWEN3})


def verify(table: FamilyTable, tokenizer: LoadedTokenizer) -> None:
    if tokenizer.chat_template_sha256 != table.chat_template_sha256:
        raise TemplateError(
            f"chat_template sha256 {tokenizer.chat_template_sha256[:16]} does not match the "
            f"{table.family} table ({table.chat_template_sha256[:16]})")
    for role, marker in table.markers.items():
        for start in (True, False):
            got = tuple(tokenizer.encode(marker.text, segment_start=start))
            if got != marker.ids:
                raise TemplateError(f"{table.family} marker {role!r} encodes to {list(got)}, table says {list(marker.ids)}")
    added = tokenizer.added_tokens
    for name, marker in table.inline.items():
        if name in table.markers:
            raise TemplateError(f"{table.family} inline marker {name!r} is also a marker role")
        # The id is read from added_tokens, not from the encoder, so a table that
        # names the wrong id fails here even if the encoder agreed with it.
        if len(marker.ids) != 1 or added.get(marker.ids[0]) != marker.text:
            raise TemplateError(f"{table.family} inline marker {name!r} must be the one added token "
                                f"{marker.text!r}, table says {list(marker.ids)}")
        # An rstrip token would absorb the whitespace that opens the next part in
        # a whole-string render, which a separately encoded part cannot reproduce.
        if marker.ids[0] in tokenizer.rstrip_ids:
            raise TemplateError(f"{table.family} inline marker {name!r} absorbs trailing whitespace")
        for start in (True, False):
            got = tuple(tokenizer.encode(marker.text, segment_start=start))
            if got != marker.ids:
                raise TemplateError(f"{table.family} inline marker {name!r} encodes to {list(got)}, "
                                    f"table says {list(marker.ids)}")


def table_for(family: str, tokenizer: LoadedTokenizer) -> FamilyTable:
    table = FAMILIES.get(family)
    if table is None:
        raise TemplateError(f"unknown template family {family!r}. This build ships {sorted(FAMILIES)}")
    verify(table, tokenizer)
    return table
