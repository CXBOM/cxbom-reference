"""Parse qwen3-native tool calls from model output, and render their inverse (spec M-4).

Owner: ATACE Working Group.

The served qwen3 model emits a tool call in its own native format, the one its
chat template documents and writes: a ``<tool_call>`` tag, a newline, a JSON
object carrying ``name`` and ``arguments``, a newline, and a ``</tool_call>``
tag. Consecutive calls are one newline apart. parse_tool_call reads that back
into structured calls, and render_tool_call is its inverse.

The tag strings come from the pinned family table (templates.QWEN3.inline),
never from a literal spelled here, so a tag that drifts from the tokenizer's own
added tokens fails the table's verify() at load rather than parsing against a
copy of itself. The wrapping that carries a tool RESULT back to the model is the
separate TOOL_RESPONSE / TOOL_RESPONSE_END pair Assembly already writes.
join_tool_result_text builds the text those markers wrap.

parse_tool_call never raises on model output. Model output is adversarial by
assumption: a truncated stream, a half-written block, or a body that is not JSON
is a parse result to report, not an exception to propagate into the agent loop.
Every block that does not yield a name-and-arguments object lands in
ToolCallParse.errors with a reason and the raw block, and the well-formed blocks
around it still parse. ToolCallError is raised only for a programming mistake in
a caller's own render inputs, never for anything a model produced.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

from .templates import QWEN3, TOOL_CALL, TOOL_CALL_END, FamilyTable


class ToolCallError(ValueError):
    """A render input the caller controls is unrenderable. parse_tool_call never raises this."""


@dataclass(frozen=True)
class ToolCall:
    """One structured call: the tool name and the JSON value the model gave as its arguments.

    ``native`` is True when the block carried the ``arguments`` key exactly as the
    qwen3 native format writes it. It is False when the key was absent and
    ``arguments`` was defaulted to ``{}``: the call is still parseable and
    executable, but a consumer that must distinguish a native-compliant call from
    a defaulted one reads this flag rather than inferring it from an empty
    ``arguments``.
    """
    name: str
    arguments: Any
    native: bool = True


@dataclass(frozen=True)
class ToolCallParseError:
    """A ``<tool_call>`` block that did not yield a call, with why and the raw block that failed.

    The block is model output the caller already holds in full, so carrying it
    here leaks nothing new. It lets the agent log or retry the exact span.
    """
    reason: str
    block: str


@dataclass(frozen=True)
class ToolCallParse:
    """The result of parsing model output: the calls that parsed and the blocks that did not."""
    calls: tuple[ToolCall, ...] = ()
    errors: tuple[ToolCallParseError, ...] = ()

    @property
    def ok(self) -> bool:
        """True when every ``<tool_call>`` block parsed (was valid JSON with a name).

        Zero blocks is ok: the model called no tool. ok is about parseability, not
        native compliance. A block missing the ``arguments`` key is parseable, so
        it does not make ok False. Its call carries ``native`` False instead (see
        ToolCall.native), which is the signal a consumer reads to tell a
        native-compliant call from a defaulted one.
        """
        return not self.errors


def _tags(table: FamilyTable) -> tuple[str, str]:
    """The open and close tag strings for a family, read from its pinned inline markers."""
    open_marker = table.inline.get(TOOL_CALL)
    close_marker = table.inline.get(TOOL_CALL_END)
    if open_marker is None or close_marker is None:
        raise ToolCallError(
            f"template family {table.family!r} carries no {TOOL_CALL!r} inline tag, so it renders no "
            "native tool call to parse or emit")
    return open_marker.text, close_marker.text


def parse_tool_call(text: str, *, table: FamilyTable = QWEN3) -> ToolCallParse:
    """Read every native tool-call block out of model output text (or its ids-decoded text).

    Handles zero, one, or many ``<tool_call>`` blocks. A block whose body is not a
    JSON object with a string ``name`` is reported in ``errors``, not raised, and a
    ``<tool_call>`` the stream never closed is reported as one unterminated block.
    Text outside any block (reasoning, whitespace, the newline between blocks) is
    ignored: it is not a call and not an error.
    """
    if not isinstance(text, str):
        raise ToolCallError(f"parse_tool_call needs the model output as str, not {type(text).__name__}")
    open_tag, close_tag = _tags(table)
    calls: list[ToolCall] = []
    errors: list[ToolCallParseError] = []
    pos = 0
    while True:
        start = text.find(open_tag, pos)
        if start == -1:
            break
        body_start = start + len(open_tag)
        end = text.find(close_tag, body_start)
        if end == -1:
            # A <tool_call> the stream never closed: a truncated generation, not a call.
            errors.append(ToolCallParseError("unterminated <tool_call> block: no closing tag", text[start:]))
            break
        block = text[start:end + len(close_tag)]
        call, reason = _parse_block(text[body_start:end])
        if reason is not None:
            errors.append(ToolCallParseError(reason, block))
        else:
            calls.append(call)
        pos = end + len(close_tag)
    return ToolCallParse(tuple(calls), tuple(errors))


def _parse_block(inner: str) -> tuple[ToolCall | None, str | None]:
    """Parse the JSON body between one pair of tags. Returns (call, None) or (None, reason)."""
    body = inner.strip()
    if not body:
        return None, "empty <tool_call> block"
    try:
        obj = json.loads(body)
    except ValueError as e:
        # json.JSONDecodeError is a ValueError. Catch the base so a truncated or
        # malformed body reports rather than escaping into the caller's loop.
        return None, f"<tool_call> body is not valid JSON: {e}"
    if not isinstance(obj, dict):
        return None, f"<tool_call> body is a JSON {type(obj).__name__}, not an object with name and arguments"
    name = obj.get("name")
    if not isinstance(name, str) or not name:
        return None, "<tool_call> object has no non-empty string 'name'"
    # The native format always writes "arguments", and a compliant no-argument
    # call writes an empty object. A missing key is read as no arguments rather
    # than a malformed block, so a legitimate no-argument call still parses, but
    # native records that the key was absent so a consumer is not misled by the
    # defaulted {} into reading the block as native-compliant.
    native = "arguments" in obj
    return ToolCall(name=name, arguments=obj.get("arguments", {}), native=native), None


def render_tool_call(name: str, arguments: Any = None, *, table: FamilyTable = QWEN3) -> str:
    """Render one call in the family's native format, the exact inverse of parse_tool_call.

    The body is the shape the qwen3 chat template writes:
    ``<tool_call>\\n{"name": "<name>", "arguments": <args>}\\n</tool_call>``, tags
    from the pinned table. json.dumps writes the template's own default separators
    (", " and ": "), so parse_tool_call returns the same name and arguments back.
    """
    open_tag, close_tag = _tags(table)
    if not isinstance(name, str) or not name:
        raise ToolCallError("a tool call name must be a non-empty string")
    if arguments is None:
        arguments = {}
    body = json.dumps({"name": name, "arguments": arguments}, ensure_ascii=False)
    return f"{open_tag}\n{body}\n{close_tag}"


def render_tool_calls(calls: Iterable[ToolCall], *, table: FamilyTable = QWEN3) -> str:
    """Render a sequence of calls, one newline between blocks, the way the template separates them."""
    return "\n".join(render_tool_call(c.name, c.arguments, table=table) for c in calls)


def join_tool_result_text(content: Iterable[Any]) -> str:
    """The text a tool result contributes inside ``<tool_response>``: each block's text, newline-joined.

    An MCP tool result carries a list of content blocks. Each text block carries a
    ``text`` field. This joins those with a single newline, the text the qwen3
    tool-response wrapper (templates.TOOL_RESPONSE ... TOOL_RESPONSE_END, which
    Assembly writes) then wraps. A block with no text (an image, an embedded
    resource) contributes nothing to the joined text.
    """
    parts: list[str] = []
    for block in content:
        text = block.get("text") if isinstance(block, dict) else getattr(block, "text", None)
        if text is None:
            continue
        if not isinstance(text, str):
            raise ToolCallError(f"a tool result text block carries a {type(text).__name__}, not str")
        parts.append(text)
    return "\n".join(parts)
