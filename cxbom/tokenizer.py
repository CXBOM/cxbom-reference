"""Pinned, offline tokenizer loading for ids mode.

Owner: ATACE Working Group.

The emitter tokenizes each part of the prompt on its own and concatenates the
ids (spec 9.1). A SentencePiece-style tokenizer such as Phi-3.5's prepends
"▁" to every string it encodes. HF tokenizers apply that prefix once per
segment, where a segment starts at the beginning of the prompt or right after
an added token such as <|system|>. Encoding every part with the prefix would
insert a spurious "▁" token at each part boundary (the Jetson probe saw
40 tokens whole and 41 per part). So this module builds two encoders from the
one pinned tokenizer.json: a segment-start encoder (the file as shipped) and a
continuation encoder with only the prefix step removed. The assembly picks the
segment-start encoder for the first part and for any part that follows a
marker, and the continuation encoder everywhere else.

Both JSON files are parsed with jsonstrict, because a duplicate key or a
non-finite number would let the pinned bytes mean different things to the
Rust loader and to this module.

Some added tokens, such as <|system|>, ship with "rstrip": true, meaning the
Rust loader drops any whitespace that immediately follows the marker in the
same encode() call. When the assembly inserts a marker as a bare id (never
running it through the Rust loader's own text scan), this module has to
absorb that leading whitespace itself, or the composed ids gain a spurious
token that whole-string encoding never produces. encode_part() does that
absorption and compose() is the reference assembly: markers are ids,
everything else is a whole scaffold string or a whole component, never a
fragment split inside a word. A part made entirely of whitespace that still
encodes to ids cannot be reattached to the word it separates once it is
encoded on its own, so encode_part() fails closed on that shape rather than
returning ids that would not match whole-string encoding. A text part that
ends in whitespace and is followed by another text part has the same defect:
its own trailing separator would be encoded as its own token instead of
attaching to the word that follows, so compose() checks one part ahead and
fails closed before encoding it. A marker breaking up two text parts is
unaffected, because a marker is inserted as a bare id and never shares an
encode() call with its neighbors.

Both of those checks are named failure shapes, not a proof of correctness for
every layout. So compose() ends with a self-check: it rebuilds the whole
prompt as a single string (substituting each marker id's literal added-token
content) and compares its own composed ids against encoding that string
directly. Any divergence, named or not, raises rather than returning ids
Task 9 has not verified.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from . import jsonstrict

PREFIX = "▁"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class TokenizerError(ValueError):
    """A tokenizer file is missing, unpinned, malformed, or has an unsupported shape."""


@dataclass(frozen=True)
class PartIds:
    """The result of encoding one part of the prompt (spec 9.1).

    absorbed counts the leading whitespace characters encode_part() stripped
    because the previous id was a marker with rstrip true. segment_start_after
    is the segment_start value the next part should use: unchanged from this
    part's own segment_start when this part produced no ids (an empty or
    fully absorbed part never opens or closes a segment), and false otherwise.
    """
    ids: tuple[int, ...]
    absorbed: int
    segment_start_after: bool


@dataclass(frozen=True)
class LoadedTokenizer:
    sha256: str
    chat_template_sha256: str
    library_version: str
    bos_ids: tuple[int, ...]
    special_ids: Mapping[str, int]
    bos_eos: frozenset[str]
    rstrip_ids: frozenset[int]
    lstrip_ids: frozenset[int]
    _start: object = field(repr=False, compare=False)
    _cont: object = field(repr=False, compare=False)
    _content_by_id: Mapping[int, str] = field(repr=False, compare=False)

    @property
    def added_tokens(self) -> Mapping[int, str]:
        """Every added token by id, special or not (Qwen3's <think> is added but not special)."""
        return self._content_by_id

    def encode(self, text: str, *, segment_start: bool) -> list[int]:
        enc = self._start if segment_start else self._cont
        return list(enc.encode(text, add_special_tokens=False).ids)

    @property
    def vocab_size(self) -> int:
        """One past the highest id the pinned file can decode, added tokens included."""
        return self._start.get_vocab_size(with_added_tokens=True)

    def decode(self, ids: list[int]) -> str:
        """The text the pinned tokenizer renders for ids, added tokens written out.

        Decoding uses the segment-start tokenizer, so on Phi-3.5 the decoder's
        Strip step removes the one space the segment-start prefix put in front
        of the first word. That is the right rendering only for ids that open a
        segment, which is why Assembly.model_output_ids takes generated ids
        only right after a marker.
        """
        return self._start.decode(list(ids), skip_special_tokens=False)

    def encode_part(self, text: str, *, prev_id: int | None, segment_start: bool) -> PartIds:
        """Encode one part, mirroring the rstrip the Rust loader applies to markers.

        prev_id is the id emitted immediately before this part (a marker id
        from compose(), or None at the very start of the prompt). It only
        matters when it names a marker with rstrip true, in which case this
        part's leading whitespace was already consumed by that marker in
        whole-string encoding and must be stripped here too.
        """
        absorbed = 0
        if prev_id is not None and prev_id in self.rstrip_ids:
            stripped = text.lstrip()
            absorbed = len(text) - len(stripped)
            text = stripped
        ids = tuple(self.encode(text, segment_start=segment_start))
        if ids and not text.strip():
            raise TokenizerError(
                f"cannot compose a whitespace-only part into ids: {text!r} would need to "
                "reattach to the word it separates, which encoding it on its own cannot do"
            )
        segment_start_after = segment_start if not ids else False
        return PartIds(ids=ids, absorbed=absorbed, segment_start_after=segment_start_after)

    def _marker_content(self, marker_id: int) -> str:
        content = self._content_by_id.get(marker_id)
        if content is None:
            raise TokenizerError(f"compose() got id {marker_id}, which is not a known marker")
        return content

    def compose(self, parts: list[str | int]) -> tuple[int, ...]:
        """Assemble ids for a full prompt from scaffold strings and marker ids.

        Each element of parts is either a whole scaffold string or component
        (str) or a marker's token id (int, from special_ids). This is the
        reference composition spec 9.1 assembly must produce: it is what
        Task 9's part-by-part emission is required to equal, and what the
        tests in this module check against whole-string encoding.

        Before encoding a text part that ends in whitespace, this looks one
        part ahead: if the next part is also text, the trailing whitespace
        cannot be reattached to the word that follows once it has already
        been encoded on its own, so this raises before trying. Following a
        marker, or being the last part, is fine, because a marker never
        shares an encode() call with the text around it.

        The composed ids are then checked against encoding the whole prompt
        as one string (each marker id expanded to its literal added-token
        content). Any difference, named above or not, raises rather than
        returning ids that do not match whole-string encoding.
        """
        ids: list[int] = []
        segment_start = True
        prev_id: int | None = None
        for i, part in enumerate(parts):
            if isinstance(part, int) and not isinstance(part, bool):
                ids.append(part)
                prev_id = part
                segment_start = True
                continue
            if not isinstance(part, str):
                raise TokenizerError(f"compose() parts must be str or int, got {type(part).__name__}")
            if part and part[-1].isspace() and part.strip():
                next_part = parts[i + 1] if i + 1 < len(parts) else None
                if isinstance(next_part, str):
                    raise TokenizerError(
                        "a part ends in whitespace before another text part. "
                        "Trim it or move the whitespace into the next part"
                    )
            result = self.encode_part(part, prev_id=prev_id, segment_start=segment_start)
            ids.extend(result.ids)
            segment_start = result.segment_start_after
            if result.ids:
                prev_id = result.ids[-1]
        composed = tuple(ids)
        whole_text = "".join(part if isinstance(part, str) else self._marker_content(part) for part in parts)
        whole_ids = tuple(self.encode(whole_text, segment_start=True))
        if composed != whole_ids:
            index = _first_diff_index(composed, whole_ids)
            raise TokenizerError(f"composed ids differ from the whole-prompt encoding at index {index}")
        return composed


def _first_diff_index(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Return the first index where a and b differ, or the length of the shorter one."""
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b))


def _read_json(path: Path, what: str) -> tuple[bytes, object]:
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        raise TokenizerError(f"cannot read {what}: {e.strerror}") from None
    try:
        return data, jsonstrict.to_python(jsonstrict.parse(data))
    except jsonstrict.StrictJSONError as e:
        raise TokenizerError(f"{what} is not strict JSON: {e}") from None


def _prefix_free(doc: dict) -> dict:
    """Return tokenizer.json with its leading-prefix step removed.

    Only the shape Phi-3.5 ships is supported: a Sequence normalizer that
    starts with Prepend("▁"). Any other place a prefix can come from
    (a Metaspace pre-tokenizer, a ByteLevel add_prefix_space) fails closed,
    because a silently different continuation encoder would shift every
    component boundary.
    """
    out = copy.deepcopy(doc)
    norm = out.get("normalizer")
    prepend = {"type": "Prepend", "prepend": PREFIX}
    if norm == prepend:
        out["normalizer"] = None
    elif isinstance(norm, dict) and norm.get("type") == "Sequence" and \
            isinstance(norm.get("normalizers"), list) and norm["normalizers"][:1] == [prepend]:
        norm["normalizers"] = norm["normalizers"][1:]
    if "Prepend" in json.dumps(out.get("normalizer")):
        raise TokenizerError("unsupported tokenizer shape: a Prepend step that is not first")
    pre = out.get("pre_tokenizer")
    steps = pre.get("pretokenizers", []) if isinstance(pre, dict) and pre.get("type") == "Sequence" else [pre]
    for step in steps:
        if not isinstance(step, dict):
            continue
        if step.get("type") == "Metaspace" and step.get("prepend_scheme", "always") != "never":
            raise TokenizerError("unsupported tokenizer shape: Metaspace prefix")
        if step.get("type") == "ByteLevel" and step.get("add_prefix_space") is True:
            raise TokenizerError("unsupported tokenizer shape: ByteLevel add_prefix_space")
    return out


def _token_content(value) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("content"), str):
        return value["content"]
    return None


def load_tokenizer(path, *, config, expected_sha256: str) -> LoadedTokenizer:
    if not isinstance(expected_sha256, str) or not _HEX64.fullmatch(expected_sha256):
        raise TokenizerError("expected_sha256 must be 64 lowercase hex characters")
    data, doc = _read_json(path, "tokenizer.json")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise TokenizerError(f"tokenizer.json sha256 {actual[:16]} does not match the pin {expected_sha256[:16]}")
    _cfg_bytes, cfg = _read_json(config, "tokenizer_config.json")
    if not isinstance(doc, dict) or not isinstance(cfg, dict):
        raise TokenizerError("tokenizer.json and tokenizer_config.json must be JSON objects")
    template = cfg.get("chat_template")
    if not isinstance(template, str) or not template:
        raise TokenizerError("tokenizer_config.json has no chat_template string")
    cont_doc = _prefix_free(doc)
    try:
        import tokenizers
        from tokenizers import Tokenizer
    except ImportError:
        raise TokenizerError("the tokenizers library is missing. Install cxbom[emit]") from None
    try:
        start = Tokenizer.from_str(data.decode("utf-8"))
        cont = Tokenizer.from_str(json.dumps(cont_doc, ensure_ascii=False))
    except Exception as e:  # the Rust loader raises a bare Exception subclass
        raise TokenizerError(f"tokenizers could not load the file: {type(e).__name__}") from None
    special: dict[str, int] = {}
    rstrip_ids: set[int] = set()
    lstrip_ids: set[int] = set()
    content_by_id: dict[int, str] = {}
    for added in doc.get("added_tokens", []):
        if not isinstance(added, dict) or not isinstance(added.get("id"), int):
            continue
        if isinstance(added.get("content"), str):
            content_by_id[added["id"]] = added["content"]
            if added.get("special") is True:
                special[added["content"]] = added["id"]
        if added.get("rstrip") is True:
            rstrip_ids.add(added["id"])
        if added.get("lstrip") is True:
            lstrip_ids.add(added["id"])
    if lstrip_ids:
        raise TokenizerError(
            f"tokenizer.json marks id {sorted(lstrip_ids)[0]} as lstrip, which this loader does not support"
        )
    bos_eos: set[str] = set()
    for key in ("bos_token", "eos_token"):
        content = _token_content(cfg.get(key))
        if content is not None and start.token_to_id(content) is not None:
            special[content] = start.token_to_id(content)
            bos_eos.add(content)
    bos_ids: tuple[int, ...] = ()
    if cfg.get("add_bos_token") is True:
        content = _token_content(cfg.get("bos_token"))
        bos_id = start.token_to_id(content) if content is not None else None
        if bos_id is None:
            raise TokenizerError("add_bos_token is true but bos_token has no id")
        bos_ids = (bos_id,)
    return LoadedTokenizer(
        sha256=actual,
        chat_template_sha256=hashlib.sha256(template.encode("utf-8")).hexdigest(),
        library_version=tokenizers.__version__,
        bos_ids=bos_ids,
        special_ids=MappingProxyType(special),
        bos_eos=frozenset(bos_eos),
        rstrip_ids=frozenset(rstrip_ids),
        lstrip_ids=frozenset(lstrip_ids),
        _start=start,
        _cont=cont,
        _content_by_id=MappingProxyType(content_by_id),
    )
