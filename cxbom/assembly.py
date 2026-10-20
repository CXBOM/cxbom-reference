"""Assembly: the emitter's public API, ids mode (spec 9.1 to 9.4).

Owner: ATACE Working Group.

The application builds its prompt through an Assembly. Each part (marker, inline tag,
separator, component) is tokenized on its own, and token_ids() is BOS plus the
concatenation, so component boundaries are exact by construction and the ids
the application sends are the ids the record counts. A part that opens the
prompt or follows a marker is encoded with the tokenizer's segment-start
encoder, and every other part with the prefix-free continuation encoder (see
tokenizer.py). On the pinned Phi-3.5 tokenizer that makes token_ids() equal
the whole-string encoding of the same text whenever no BPE merge would span a
part boundary and no part after a marker starts with whitespace (Phi-3.5
markers absorb trailing whitespace in a whole-string encoding).

_append() self-checks every marker-adjacent part (the first part of the
prompt, and every part right after a marker) against encoding that marker's
own text immediately followed by the part's text as one whole string, before
the part can enter self._parts. A mismatch there means the part started with
whitespace the marker's rstrip would have silently absorbed in a whole-string
render, so ids mode's separately-encoded token for that whitespace is not
what the model actually sees. The check is scoped to marker adjacency, not
the whole prompt: two ordinary components placed back to back can
legitimately diverge from whole-string encoding when a BPE merge would span
their boundary, and that divergence is ids mode's own boundary-preserving
guarantee working as intended, not a bug (see
test_adjacent_json_components_keep_exact_boundaries). Because the check runs
at append time and raises before the part is stored, a refused part never
reaches self._parts or self._components, and the assembly stays usable for
whatever the caller appends next.

model_output_ids() is the one path that takes ids rather than text: the ids a
model generated re-enter verbatim, because re-tokenizing their decoding can
give different ids (premortem K13). The part's text is their decoding, so for
that part text() renders token_ids() rather than the other way round. It is
refused anywhere but right after the marker that ends the generation prompt,
and it refuses every added control token but the inline tags and a ruled
stop, so it cannot place a marker that marker() did not.

Positions come from the open role region, never from the caller. Tool
definitions and server instructions take proxy_session explicitly, and that
ProxySession must come from binding.session_from_meta applied to a list,
initialize or discover result, never from a tools/call result (spec 9.2, and
session_from_meta's docstring explains why this module cannot enforce that on
its own). A bound item's text comes from the store through the signed renderer,
and an unbound item needs the caller's exact text. emit() rechecks every
binding, builds the record, runs the vendored validator and consistency.py
over it, and refuses to return a record that fails either.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from os import PathLike
from typing import Callable, Sequence

from . import conformance, consistency, paths
from .binding import SERVER_ID, BindingError, LogMissingError, ProxySession, Resolved, Verifier
from .canonical import canonical
from .emitter import GLOSSARY_FIXED, BlockedItem, ComponentFacts, RecordInputs, ScanResult, build_record
from .launchpolicy import REGISTRY_RUNNERS
from .state import BLOCKED, PINNED_MATCH
from .templates import CLOSE, TAG_ONLY, THINK_OFF, TOOL_RESPONSE, TOOL_RESPONSE_END, TemplateError, table_for
from .timeutil import now_rfc3339, parse_time
from .tokenizer import LoadedTokenizer

_CID = re.compile(r"^cc-\d+$")
_SESSION = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SERVING = re.compile(r"^[A-Za-z0-9 ._/+:-]{1,64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# A host:port pair anywhere in serving names a network endpoint, which the record must not carry.
_HOST_PORT = re.compile(r"[A-Za-z0-9.-]+:\d+")
_SCAN_STATUS = {"clean", "scanned-with-warnings", "scanned-with-failures", "not-scanned"}
_RATINGS = {"critical", "high", "medium", "low", "none"}
# The <tool_response> wrapper as a sequence: what each stage of an open wrapper
# admits next, and by omission everything it refuses. Assembly._wrapper_admits
# reads this and nothing else, so the rule is this table. The keys are the stages
# the wrapper passes through; the values name a component method ('tool_result')
# or a marker role, which never collide.
_WRAPPER_NEXT = {"open": "tool_result", "filled": TOOL_RESPONSE_END, "closed": CLOSE}
# The only region an inline marker may go in: the family templates write their
# inline tags (qwen3's <tool_call> and </tool_call>) in the system prompt's tool
# instructions. The <tool_response> wrapper opens the user region, so keeping
# this set free of 'user' is what stops an inline marker from landing inside a
# wrapper, by construction rather than by a second wrapper check.
_INLINE_REGIONS = frozenset({"system"})
# The tokens a generation may end on, by content (controller rulings,
# 2026-09-27). The first is the token marker('end') opens with, which writes it
# back. The served llama.cpp qwen3 GGUF ends generation on six ids, so
# model_output_ids accepts all six as the final id while the close marker still
# opens with <|im_end|>. The Qwen3 template writes <|im_end|> after every
# assistant turn whichever id stopped generation. Five of the six carry an
# added-token content name in the pinned tokenizer and resolve by content like
# the original two: <|endoftext|>, plus <|fim_pad|>, <|repo_name|> and
# <|file_sep|>, which the served GGUF lists as end-of-generation ids. Any other
# added token in the final position refuses, so a stop the rulings did not name
# fails loud rather than entering the prompt as content.
_TERMINAL_STOPS = {
    "qwen3": ("<|im_end|>", "<|endoftext|>", "<|fim_pad|>", "<|repo_name|>", "<|file_sep|>"),
    "phi3": ("<|end|>",),
}
# The sixth qwen3 end-of-generation id, 128247, is a plain vocabulary token (it
# decodes to </s>), not an added token, so no content name resolves it. It is
# allowed by numeric id rather than a fabricated name, and refused in the body
# exactly like a named stop. phi3 has no such id.
_TERMINAL_STOP_IDS = {"qwen3": (128247,)}


class AssemblyError(ValueError):
    """The assembly was built or used incorrectly, or its record failed validation."""


def ids_sha256(ids: Sequence[int]) -> str:
    """SHA-256 of the RFC 8785 JSON array of token ids, the value emit() compares."""
    return hashlib.sha256(canonical(list(ids))).hexdigest()


@dataclass(frozen=True)
class ModelInfo:
    family: str
    version: str
    provider: str
    revision: str
    context_window_max: int
    architecture_type: str


@dataclass(frozen=True)
class AgentInfo:
    id: str
    name: str
    version: str
    operator: str
    environment: str
    deployment_id: str


@dataclass(frozen=True)
class ControlLayer:
    layer_id: str
    designation: str
    description: str
    owasp_coverage: Sequence[str]
    coverage_gaps: Sequence[str]
    controls_active: Sequence[str] = ()
    controls_inactive: Sequence[str] = ()
    agentic_coverage: Sequence[str] = ()

    def as_record(self) -> dict:
        out = {"layerId": self.layer_id, "designation": self.designation, "description": self.description,
               "owaspCoverage": list(self.owasp_coverage), "controlsActive": list(self.controls_active),
               "controlsInactive": list(self.controls_inactive),
               "status": "partial" if self.coverage_gaps else "active", "coverageGaps": list(self.coverage_gaps)}
        if self.agentic_coverage:
            out["agenticCoverage"] = list(self.agentic_coverage)
        return out


@dataclass(frozen=True)
class Ring:
    ring: int
    designation: str
    description: str
    control_layer: str
    integrity_requirement: str
    allowed_sources: Sequence[str]
    external_sources_permitted: bool


@dataclass(frozen=True)
class TrustModel:
    description: str
    rings: Sequence[Ring]

    @classmethod
    def three_ring(cls) -> "TrustModel":
        return cls("Three pre-inference trust rings. Ring labels confer no computational privilege.", (
            Ring(0, "operator", "Operator-authored instructions.", "system-prompt", "cryptographic",
                 ("operator",), False),
            Ring(1, "agent", "Agent-mediated content: tools, retrieval, model output.", "tool-execution",
                 "hash-verified", ("mcp-server", "retrieval", "model-generated"), True),
            Ring(2, "user", "User input.", "ingress", "sanitized", ("user",), False)))

    def as_record(self) -> dict:
        return {"description": self.description, "rings": [
            {"ring": r.ring, "designation": r.designation, "description": r.description,
             "controlLayer": r.control_layer, "integrityRequirement": r.integrity_requirement,
             "allowedSources": list(r.allowed_sources), "externalSourcesPermitted": r.external_sources_permitted}
            for r in self.rings]}


@dataclass
class _Part:
    kind: str                       # marker, inline, sep, component
    text: str
    ids: list[int]


@dataclass
class _Component:
    cid: str
    method: str
    text: str
    ids: list[int]
    turn: int
    position: str
    region: str
    server_id: str | None = None
    name: str | None = None
    origin: str | None = None
    uri: str | None = None
    session: ProxySession | None = None
    resolved: Resolved | None = None
    special_role: tuple[str, ...] = ()
    special_other: tuple[str, ...] = ()
    # The flagged tokens of each rank that the text spells and the ids do not carry.
    role_spelled: tuple[str, ...] = ()
    other_spelled: tuple[str, ...] = ()
    # Set only by model_output_ids: ids_sha256 of the ids exactly as generated.
    generated_ids_sha256: str | None = None
    # The id that ended the generation, or None for a generation cut off first.
    generated_stop: int | None = None


_UVX_VALUE_FLAGS = {"--from", "--with"}


def _uvx_package(rest: list[str]) -> str | None:
    """The uvx package argument: --from's value if given, else the first non-flag token.

    A value-taking flag such as --with can be followed by a token that
    itself carries no leading dash (e.g. "dep==1.0" in "--with dep==1.0"), so
    a naive "first token without a dash" scan would misread that value as
    the package and wrongly call an unpinned package version-pinned.
    """
    package, from_value, i = None, None, 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--from" and i + 1 < len(rest):
            from_value = rest[i + 1]
            i += 2
            continue
        if tok in _UVX_VALUE_FLAGS:
            i += 2
            continue
        if not tok.startswith("-") and package is None:
            package = tok
        i += 1
    return from_value if from_value is not None else package


def _first_non_flag(rest: list[str], skip: frozenset[str] = frozenset()) -> str | None:
    for tok in rest:
        if tok in skip or tok.startswith("-"):
            continue
        return tok
    return None


def version_pinned(entry: dict | None) -> bool:
    """spec 9.4 allowlist for serverVersionPinned.

    Only the package (or image) argument counts, never any flag's value: a
    launcher flag can carry a version-shaped string that names something
    other than the pinned package (Task 10 ruling minor 4).
    """
    if entry is None:
        return False
    argv = entry["argv"]
    launcher = Path(argv[0]).name
    rest = argv[1:]
    if launcher == "uvx":
        package = _uvx_package(rest)
        return package is not None and bool(re.fullmatch(r"[A-Za-z0-9_.\[\],-]+==[A-Za-z0-9_.+!-]+", package))
    if launcher == "npx":
        package = _first_non_flag(rest)
        return package is not None and \
            bool(re.fullmatch(r"(@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+@\d+\.\d+\.\d+", package))
    if launcher == "pipx":
        return rest[:1] == ["run"] and any(re.fullmatch(r"[A-Za-z0-9_.\[\],-]+==[A-Za-z0-9_.+!-]+", a)
                                           for a in rest[1:])
    if launcher == "docker":
        image = _first_non_flag(rest, skip=frozenset({"run"}))
        return image is not None and bool(re.search(r"@sha256:[0-9a-f]{64}$", image))
    # Every other runner in the section 6 runner table, and the forms above
    # with any other argv, fetch from a registry, so local file or tree pins
    # say nothing about the version that runs.
    if launcher.casefold() in REGISTRY_RUNNERS:
        return False
    return bool(entry["files"] or entry["trees"])


def _safe_server_string(value: str) -> str:
    """A server-chosen string, redacted to a stable hash when it would leak.

    A tool's name (spec 9.2) comes straight from a server the proxy does not
    trust to pick safe strings, whether the tool was blocked or assembled.
    Recording it verbatim in a finding or a component label lets a malicious
    server put a local path, a file: URI, an IP literal, an email address,
    or a home-path pattern into the record, which
    consistency.anonymity then refuses record-wide, permanently blocking
    emit() instead of failing just this one field (Task 10 ruling critical
    1). The hash is stable, so the same server-chosen string always redacts
    to the same value, and it never contains the original bytes.
    """
    if consistency.leaks_location(value) or consistency.looks_like_home_path(value):
        return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
    return value


def _path_arg(label: str, value, *, optional: bool) -> Path | None:
    """A caller-supplied path argument as a Path, refusing anything else with AssemblyError.

    Path() raises a bare TypeError for an int or a dict, which is not a
    failure shape the Assembly promises its caller.
    """
    if value is None and optional:
        return None
    if not isinstance(value, (str, PathLike)) or (isinstance(value, str) and not value):
        raise AssemblyError(f"{label} must be a path")
    return Path(value)


def _account(resolve: Callable[[], Path]) -> Path:
    """Call a paths resolver, turning a missing passwd entry into AssemblyError.

    paths resolves every cxbom location from pwd.getpwuid, never from HOME. A
    uid with no passwd entry (a container started with an arbitrary --user,
    for one) makes getpwuid raise KeyError, and that bare KeyError is not a
    failure shape the Assembly promises its caller (final review I3).
    """
    try:
        return resolve()
    except KeyError:
        raise AssemblyError("the current user has no passwd entry, so cxbom cannot resolve its "
                            "state, config, or home directory") from None


class Assembly:
    def __init__(self, *, model: ModelInfo, tokenizer: LoadedTokenizer, template_family: str, mode: str,
                 server_bos: bool, agent: AgentInfo, control_layers: Sequence[ControlLayer], lock, serving: str,
                 trust_model: TrustModel | None = None,
                 scanner: Callable[[str, str], ScanResult] | None = None,
                 state_dir: Path | None = None, config_dir: Path | None = None):
        if not isinstance(model, ModelInfo) or not isinstance(agent, AgentInfo):
            raise AssemblyError("model must be a ModelInfo and agent an AgentInfo")
        if not isinstance(tokenizer, LoadedTokenizer):
            raise AssemblyError("tokenizer must come from load_tokenizer")
        if mode != "ids":
            raise AssemblyError(f"mode {mode!r} is not supported by this build. Use mode='ids'")
        if server_bos is not False:
            raise AssemblyError("server_bos must be False: the emitter puts BOS in token_ids() itself")
        # serving lands in the content.tokenCount glossary entry, so it must name the
        # implementation and never the endpoint it runs on (final review I2).
        if not isinstance(serving, str) or not _SERVING.fullmatch(serving) or "://" in serving or \
                _HOST_PORT.search(serving) or consistency.leaks_location(serving) or \
                consistency.looks_like_home_path(serving):
            raise AssemblyError("serving must name the implementation, for example 'llama.cpp /completion', "
                                "with no host, port, IP address, or path")
        if not isinstance(control_layers, (list, tuple)) or \
                not all(isinstance(layer, ControlLayer) for layer in control_layers):
            raise AssemblyError("control_layers must be a list or tuple of ControlLayer values")
        if not isinstance(template_family, str):
            raise AssemblyError("template_family must be a string, for example 'phi3'")
        lock = _path_arg("lock", lock, optional=True)
        state_dir = _path_arg("state_dir", state_dir, optional=True)
        config_dir = _path_arg("config_dir", config_dir, optional=True)
        if scanner is not None and not callable(scanner):
            raise AssemblyError("scanner must be callable or None")
        if not isinstance(model.context_window_max, int) or model.context_window_max < 1:
            raise AssemblyError("model.context_window_max must be a positive integer")
        try:
            self.table = table_for(template_family, tokenizer)
        except TemplateError as e:
            raise AssemblyError(str(e)) from None
        state = _account(paths.state_dir) if state_dir is None else Path(state_dir)
        if state_dir is not None and paths.inside_git_worktree(state):
            raise AssemblyError("state_dir must not be inside a git worktree")
        self.model, self.agent, self.tok, self.serving = model, agent, tokenizer, serving
        self.control_layers = list(control_layers)
        self.trust_model = trust_model or TrustModel.three_ring()
        self.scanner = scanner
        try:
            # Verifier itself refuses a state_dir inside a git worktree (spec 13,
            # Task 8 ruling). The explicit check above already covers a caller-supplied
            # state_dir with an AssemblyError, and this catches the default path too
            # (paths.state_dir() landing under a git-tracked tree), so every route
            # into Assembly surfaces the same exception type.
            self.verifier = Verifier(lock=None if lock is None else Path(lock), state_dir=state,
                                     config_dir=_account(paths.config_dir) if config_dir is None
                                     else Path(config_dir))
        except BindingError as e:
            raise AssemblyError(str(e)) from None
        self._parts: list[_Part] = []
        self._components: list[_Component] = []
        self._observed: dict[tuple[str, str], ProxySession] = {}
        self._region: str | None = None
        # How far along the wrapper sequence the open region is, or None outside a
        # wrapper region. _wrapper_admits reads it to decide what may come next.
        # One field, not two booleans: the sequence has three stages, and two
        # booleans have a fourth combination that means nothing, which is the
        # representational slack a half-applied state transition hides in.
        self._wrapper: str | None = None
        # Only added-token ids count as marker ids. A qwen3 marker also carries
        # plain text ids (the role word, the newline), and flagging those would
        # mark every component that contains a newline as carrying a role marker.
        # The think block and the tool-response wrapper tags are scaffold, not
        # role or turn markers, so their added tokens (<think>, </think>,
        # <tool_response>, </tool_response>) rank as other special tokens
        # (spec 13, the 'Special token, other' row). The inline tags (<tool_call>,
        # </tool_call>) are scaffold on the same reading.
        added = tokenizer.added_tokens
        role_markers = [m for r, m in self.table.markers.items() if r not in TAG_ONLY]
        marker_ids = {i for m in role_markers for i in m.ids if i in added}
        self._role_strings = {m.text.strip() for m in role_markers} | {added[i] for i in marker_ids}
        # Every added token counts as an other special token in content, flagged
        # or not: the pinned tokenizer turns its string into its one id, so the
        # model reads it as a control token (qwen3's <|fim_pad|>, phi3's </s>).
        self._other_strings = (set(tokenizer.special_ids) | set(added.values())) - self._role_strings
        self._marker_ids = marker_ids
        self._special_by_id = {i: s for s, i in tokenizer.special_ids.items()} | dict(added)
        # model_output_ids by construction: an allowlist, never a denylist. Every
        # added token and every special id refuses in generated ids, except the
        # two sets below, both resolved from the pinned tokenizer by content.
        # A body may carry the family's inline tags, which the template writes in
        # an assistant tool call. The last id may be a ruled stop, which leaves
        # the component and is closed by marker('end').
        # templates.verify already bound each inline tag's id to the added token
        # whose content is the tag, so the table's ids are the by-name ids.
        by_content = {c: i for i, c in added.items()}
        stops = _TERMINAL_STOPS[self.table.family]
        if any(name not in by_content for name in stops):
            raise AssemblyError(f"the {self.table.family} tokenizer lacks an added token in {list(stops)}")
        self._eog = by_content[stops[0]]
        if self._eog != self.table.markers[CLOSE].ids[0]:
            raise AssemblyError(f"{stops[0]} is not the id {self.table.family} marker('end') opens with")
        # A served stop with no added-token content name is allowed by numeric
        # id. It must be a real vocabulary id, and it must not shadow a name: an
        # id the tokenizer carries as an added token is named above, never
        # listed here, so the two routes never disagree about the same id.
        stop_ids = _TERMINAL_STOP_IDS.get(self.table.family, ())
        for i in stop_ids:
            if not 0 <= i < tokenizer.vocab_size:
                raise AssemblyError(f"{self.table.family} numeric terminal id {i} is outside the pinned vocabulary")
            if i in added:
                raise AssemblyError(f"{self.table.family} numeric terminal id {i} is an added token, so name it "
                                    "in _TERMINAL_STOPS instead")
        self._terminal = frozenset(by_content[name] for name in stops) | frozenset(stop_ids)
        self._generated_body = frozenset(i for m in self.table.inline.values() for i in m.ids)
        # Every added token and special id refuses in the body, and so does a
        # numeric-id stop: it may only end a generation, never sit inside one,
        # the same rule the named stops follow by already being added tokens.
        self._generated_refused = (frozenset(added) | frozenset(tokenizer.special_ids.values())
                                   | frozenset(stop_ids)) - self._generated_body

    def _append(self, kind: str, text: str, *, label: str) -> list[int]:
        """Encode one part, checked before it can enter self._parts.

        A part that fails either check below raises here, before
        self._parts.append(), so it never enters self._parts and (through
        _component) never enters self._components either. The assembly stays
        usable afterward: a caller that catches the error and appends a
        different, valid part next still gets a working emit().

        First, text must round-trip through UTF-8. A lone surrogate would
        otherwise reach the tokenizer's Rust binding, which raises its own
        bare TypeError instead of a caller-recognizable AssemblyError.

        Second, a part that opens the prompt or follows a marker must encode
        the way the tokenizer would encode it as one string together with
        whatever came right before it. A mismatch there means this part
        starts with whitespace a marker's rstrip would have silently
        absorbed in a whole-string render, so this per-part token for the
        whitespace is not what the model would actually see.
        """
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            raise AssemblyError(f"{label}: text contains a lone surrogate and cannot be tokenized") from None
        start = not self._parts or self._parts[-1].kind == "marker"
        ids = self.tok.encode(text, segment_start=start)
        if start:
            prev = self._parts[-1] if self._parts else None
            prefix_text = prev.text if prev is not None else ""
            prefix_ids = list(prev.ids) if prev is not None else []
            whole = self.tok.encode(prefix_text + text, segment_start=True)
            if prefix_ids + ids != whole:
                raise AssemblyError(
                    f"{label}: text must not start with whitespace a role marker's rstrip would "
                    "silently absorb in a whole-string render. This is checked at the start of the "
                    "prompt and right after every marker")
        self._parts.append(_Part(kind, text, ids))
        return ids

    def _append_generated(self, text: str, ids: list[int]) -> list[int]:
        """Store ids the model generated as one component part, verbatim.

        Only model_output_ids reaches this, through _component, after its own
        checks. Neither _append check applies: the ids are not an encoding of
        text but what the model produced right after the preceding marker, and
        text is their decoding. Re-encoding them is the change the ids path
        exists to prevent. _append keeps its own signature because the Jetson's
        lab/j1 equivalence test reads it.
        """
        ids = list(ids)
        self._parts.append(_Part("component", text, ids))
        return ids

    def _wrapper_admits(self, what: str, label: str) -> None:
        """Refuse anything the open <tool_response> wrapper does not admit next.

        The wrapper is a fixed sequence: marker('tool_response'), one
        tool_result component, marker('tool_response_end'), marker('end'). That
        one invariant is the whole rule, and _WRAPPER_NEXT is it as data: each
        stage admits exactly one thing and refuses everything else by name.

        Every separate wrapper rule this replaces was one reading of that
        sequence -- the close marker needs an open wrapper, it needs the tool
        result behind it, the region cannot close while the wrapper is open, and
        nothing may follow the close. Reading the sequence once instead closes
        the cases each of them missed. Two of them tested a part kind rather than
        the sequence, so sep() walked past both: sep(' ') as the wrapper's whole
        content satisfied "the part behind the close marker is not a marker" and
        produced a wrapper the record carried no component for, and sep(' ')
        after the close marker landed between </tool_response> and <|im_end|>
        where the template writes nothing. Neither was reachable through a
        component, which is why a component-shaped rule could not see them.

        The stage also decides the kind and the count, which is what stops a
        record from describing a turn the prompt did not contain. A user_turn
        inside the wrapper is the case that matters: the prompt is byte-identical
        to the tool_result one, down to ids_sha256, while the record calls the
        span a ring-2 first-party user turn instead of a ring-1 third-party tool
        result. Both records pass the validator and the consistency check, so
        nothing downstream can tell them apart.

        Called before the part is encoded and before it is appended, never after.
        A refusal that lets the part land first leaves the prompt carrying text
        the record does not describe, which is the failure this rule exists to
        make impossible.
        """
        stage = self._wrapper
        if stage is None:
            # Outside a wrapper region the sequence says nothing, except that the
            # close marker has no wrapper to close.
            if what == TOOL_RESPONSE_END:
                raise AssemblyError(f"marker({TOOL_RESPONSE_END!r}) with no open tool response")
            return
        if what == _WRAPPER_NEXT[stage]:
            return
        # Either unclosed stage refuses the region close for the same reason: the
        # prompt would carry an opened <tool_response> that the template never
        # leaves unclosed. A closed wrapper admits it, above.
        if what == CLOSE:
            raise AssemblyError(f"close the wrapper with marker({TOOL_RESPONSE_END!r}) before marker('end')")
        if stage == "open":
            # An empty wrapper would also put the close marker's leading newline
            # right after the open marker's trailing one, which a whole-string
            # render merges into one id. _append would refuse that, but with a
            # message about marker rstrip rather than the real cause, so the real
            # cause is named here.
            if what == TOOL_RESPONSE_END:
                raise AssemblyError(f"marker({TOOL_RESPONSE_END!r}) needs the tool result between it and "
                                    f"marker({TOOL_RESPONSE!r})")
            raise AssemblyError(f"{label}: the tool response wrapper holds one tool result and nothing else, "
                                f"so {what!r} cannot go inside it")
        if stage == "filled":
            raise AssemblyError(f"{label}: the tool response wrapper already holds its tool result, so {what!r} "
                                f"cannot go inside it; close it with marker({TOOL_RESPONSE_END!r}) first")
        # Closed. The template writes only <|im_end|> after </tool_response>.
        if what == TOOL_RESPONSE_END:
            raise AssemblyError(f"marker({TOOL_RESPONSE_END!r}) with no open tool response")
        raise AssemblyError(f"{label}: the tool response wrapper is already closed, so {what!r} "
                            "would land outside it")

    def marker(self, role: str) -> None:
        if not isinstance(role, str) or role not in self.table.markers:
            raise AssemblyError(f"{self.table.family} has no marker {role!r}")
        # A marker that opens a region is refused while any region is open. That
        # runs first so the wrapper rule below only ever answers for the markers
        # that can legally appear inside an open region, and so a second wrapper
        # open still reports the region rather than the wrapper stage.
        if role not in (THINK_OFF, TOOL_RESPONSE_END, CLOSE) and self._region is not None:
            raise AssemblyError(f"marker({role!r}) while the {self._region!r} region is open")
        self._wrapper_admits(role, label=f"marker({role!r})")
        if role == THINK_OFF:
            # The empty think block is template scaffold that Qwen3 writes right
            # after the assistant marker. It is a marker part, so the overhead
            # count (every id outside a component) takes it with no extra rule,
            # and the region stays the assistant's.
            prev = self._parts[-1] if self._parts else None
            if self._region != "assistant" or prev is None or prev.kind != "marker" or \
                    prev.text != self.table.markers["assistant"].text:
                raise AssemblyError(f"marker({THINK_OFF!r}) must directly follow marker('assistant')")
        elif role == TOOL_RESPONSE_END:
            # The wrapper close carries no <|im_end|>. It sits inside the region
            # its open marker started, and marker('end') writes the region close
            # right after it.
            self._wrapper = "closed"
        elif role == CLOSE:
            if self._region is None:
                raise AssemblyError("marker('end') with no open region")
            self._region = None
            self._wrapper = None
        else:
            # The tool-response marker opens the user turn the template puts a
            # tool result in, so the region is 'user' and every position rule
            # that reads the region keeps working.
            self._region = "user" if role == TOOL_RESPONSE else role
            self._wrapper = "open" if role == TOOL_RESPONSE else None
        self._append("marker", self.table.markers[role].text, label=f"marker({role!r})")

    def inline_marker(self, name: str) -> None:
        """Append one of the family's inline tags as template overhead (spec 9.2).

        An inline tag is a single added token the template writes inside a turn,
        such as qwen3's <tool_call> in the system prompt's call-format line. The
        name is looked up in the family table and never taken as an id, so a
        caller cannot place an arbitrary token. The part adds no component and no
        contextComponents entry: its id counts in templateOverheadTokens, the way
        a marker's ids do, and its text lands in text() at the same place its id
        lands in token_ids(). It opens and closes no region, and the part after it
        is encoded as a continuation, the rule the Jetson reference applies after
        its own scaffold append. A family with no inline tag of that name refuses,
        and so does any region but system, which by construction includes the
        user region a <tool_response> wrapper occupies.
        """
        if not isinstance(name, str) or name not in self.table.inline:
            raise AssemblyError(f"{self.table.family} has no inline marker {name!r}")
        if self._region not in _INLINE_REGIONS:
            raise AssemblyError(f"inline_marker({name!r}) belongs in the 'system' region, not {self._region!r}")
        self._append("inline", self.table.inline[name].text, label=f"inline_marker({name!r})")

    def sep(self, text: str) -> None:
        if not isinstance(text, str) or not text or not text.isspace():
            raise AssemblyError("sep() accepts whitespace only")
        self._wrapper_admits("sep", label="sep()")
        self._append("sep", text, label="sep()")

    def _component(self, cid: str, method: str, text, turn: int, position: str, need_region: str | None,
                   ids: list[int] | None = None, **extra) -> _Component:
        if not isinstance(cid, str) or not _CID.fullmatch(cid):
            raise AssemblyError(f"component id {cid!r} must match cc-<digits>")
        if any(c.cid == cid for c in self._components):
            raise AssemblyError(f"component id {cid!r} is already used")
        if not isinstance(text, str) or not text.strip():
            raise AssemblyError(f"{cid}: component text must be a non-empty, non-whitespace string")
        if self._region is None:
            raise AssemblyError(f"{cid}: open a role region with marker() first")
        if need_region is not None and self._region != need_region:
            raise AssemblyError(f"{cid}: {method} belongs in the {need_region!r} region, not {self._region!r}")
        self._wrapper_admits(method, label=cid)
        if not isinstance(turn, int) or isinstance(turn, bool) or turn < 0:
            raise AssemblyError(f"{cid}: turn must be a non-negative integer")
        ids = self._append("component", text, label=cid) if ids is None else self._append_generated(text, ids)
        # Only after the append: _append refuses a payload whose leading
        # whitespace run would merge into the open marker, and advancing the stage
        # before that raise would leave an unfilled wrapper claiming to hold its
        # tool result, so the next marker('tool_response_end') would close an
        # empty one.
        if self._wrapper == "open":
            self._wrapper = "filled"
        role_ids = {self._special_by_id.get(i, f"id:{i}") for i in ids if i in self._marker_ids}
        other_ids = {self._special_by_id[i] for i in ids
                     if i in self._special_by_id and i not in self._marker_ids}
        role = tuple(sorted({s for s in self._role_strings if s in text} | role_ids))
        other = tuple(sorted(({s for s in self._other_strings if s in text} | other_ids) - set(role)))
        # Spelled, per token: a flagged string none of whose control tokens the
        # ids carry. A role string such as '<|im_start|>user' counts as carried
        # when its <|im_start|> id is present. Only generated ids can spell one,
        # because the text path's encoder turns each such string into its id.
        carried = role_ids | other_ids
        role_spelled = tuple(s for s in role if not any(c in s for c in carried))
        other_spelled = tuple(s for s in other if not any(c in s for c in carried))
        comp = _Component(cid, method, text, ids, turn, position, self._region, special_role=role,
                          special_other=other, role_spelled=role_spelled, other_spelled=other_spelled, **extra)
        self._components.append(comp)
        return comp

    def system_prompt(self, cid: str, *, text: str) -> None:
        self._component(cid, "system_prompt", text, 0, "prepended", "system")

    def user_turn(self, cid: str, *, text: str, turn: int) -> None:
        self._component(cid, "user_turn", text, turn, f"user-turn-{turn}", "user")

    def model_output(self, cid: str, *, text: str, turn: int) -> None:
        if not isinstance(turn, int) or isinstance(turn, bool) or turn < 1:
            raise AssemblyError(f"{cid}: model output re-enters after a turn, so turn must be 1 or more")
        self._component(cid, "model_output", text, turn, f"model-output-turn-{turn}", "assistant")

    def model_output_ids(self, cid: str, *, ids: Sequence[int], turn: int) -> None:
        """Append the ids the model generated, verbatim, as model output (premortem K13).

        Re-tokenizing decoded output can give different ids, so the next prompt
        would carry ids the model never produced. On qwen3 that can even turn a
        tag the model spelled as plain text into the added token itself. So the
        generated ids enter token_ids() unchanged, and the component's text is
        their decoding.

        Pass the generation's ids exactly as the server returned them. When the
        last id is the id the family's marker('end') opens with (qwen3
        <|im_end|>, phi3 <|end|>), it is the model's own turn close: it is not
        part of the component, and the caller closes the region with
        marker('end'), which writes that same id back. qwen3 may also stop on
        <|endoftext|>: that id is dropped the same way, and marker('end') writes
        the template's <|im_end|> in its place, as the Qwen3 template does after
        every assistant turn. The record says which stop id ended the generation,
        so it shows the model emitted <|endoftext|> and the template closed the
        turn. A generation cut off before any stop id enters whole. Either way
        the part equals what model_output(text) appends for any text
        model_output accepts that encodes to the same ids. model_output refuses
        text that opens with whitespace a marker would absorb, and this accepts
        the ids for it, because the model generated them.

        Refused, before anything is appended: ids that are not a list or tuple of
        ints, an id outside the pinned vocabulary, any added or special token
        but the family's inline tags in the body and a ruled stop as the last id
        (so raw ids cannot place a marker that marker() did not, and a stop no
        ruling names fails loud), ids whose decoding holds a replacement
        character (a cut inside a multi-byte character produces one, and so
        does a real U+FFFD in the output, which the text path would accept. The
        decoding cannot tell the two apart, so both refuse), and ids
        anywhere but right after the marker that ends the
        generation prompt in the assistant region. That last rule also keeps
        them out of the user region a <tool_response> wrapper occupies. The
        record carries ids_sha256 of the ids as passed, terminal id included, and
        the stop id, in the content.sha256 glossary entry, because 0.2.0 has no
        component field for either.
        """
        if not isinstance(turn, int) or isinstance(turn, bool) or turn < 1:
            raise AssemblyError(f"{cid}: model output re-enters after a turn, so turn must be 1 or more")
        if not isinstance(ids, (list, tuple)) or \
                not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
            raise AssemblyError(f"{cid}: ids must be a list or tuple of ints")
        generated = list(ids)
        vocab = self.tok.vocab_size
        if any(not 0 <= i < vocab for i in generated):
            raise AssemblyError(f"{cid}: ids must lie in the pinned vocabulary, 0 to {vocab - 1}")
        stop = generated[-1] if generated[-1:] and generated[-1] in self._terminal else None
        content = generated if stop is None else generated[:-1]
        refused = sorted({i for i in content if i in self._generated_refused})
        if refused:
            raise AssemblyError(f"{cid}: generated ids may carry no added control token but the inline tags "
                                f"{sorted(self._generated_body)}, and a ruled stop {sorted(self._terminal)} only as "
                                f"the last id. Got {refused}")
        if self._region == "assistant" and self._parts[-1].kind != "marker":
            raise AssemblyError(f"{cid}: generated ids go right after the marker that ends the generation prompt")
        text = self.tok.decode(content)
        if "\ufffd" in text:
            raise AssemblyError(f"{cid}: the ids do not decode to whole characters")
        self._component(cid, "model_output", text, turn, f"model-output-turn-{turn}", "assistant", ids=content,
                        generated_ids_sha256=ids_sha256(generated), generated_stop=stop)

    def retrieved_document(self, cid: str, *, text: str, turn: int, origin: str, uri: str) -> None:
        if not isinstance(origin, str) or not origin or not isinstance(uri, str) or not uri:
            raise AssemblyError(f"{cid}: retrieved_document needs origin and uri")
        # Spec 3 forbids absolute paths and IP addresses in a record. origin and uri
        # come straight from the caller and land in the record (origin also in the
        # component's label), so both are checked here rather than trusted. The
        # message is fixed and never echoes the refused value.
        if consistency.leaks_location(origin) or consistency.leaks_location(uri):
            raise AssemblyError(
                f"{cid}: retrieved_document origin and uri must not be a local path, a file: URI, "
                "an IP literal, or an email address")
        self._component(cid, "retrieved_document", text, turn, "retrieved-content", None, origin=origin, uri=uri)

    def tool_result(self, cid: str, *, text: str, turn: int, server_id: str, tool_name: str) -> None:
        self._check_server(server_id)
        if not isinstance(tool_name, str) or not tool_name:
            raise AssemblyError(f"{cid}: tool_name is required")
        self._component(cid, "tool_result", text, turn, f"tool-result-turn-{turn}", None,
                        server_id=server_id, name=tool_name)

    def _check_server(self, server_id: str) -> None:
        if not isinstance(server_id, str) or not SERVER_ID.fullmatch(server_id):
            raise AssemblyError(f"server_id {server_id!r} is not a valid server id")

    def _tool_position(self) -> str:
        if self._region is None:
            raise AssemblyError("open a role region with marker() first")
        return "tool-schema-block" if self._region == "system" else f"tool-definitions-{self._region}-region"

    def _bound(self, cid: str, kind: str, server_id: str, name: str | None, proxy_session, text) -> None:
        self._check_server(server_id)
        position = self._tool_position()
        if proxy_session is not None and not isinstance(proxy_session, ProxySession):
            raise AssemblyError(f"{cid}: proxy_session must come from session_from_meta or be None")
        try:
            resolved = self.verifier.resolve(kind, server_id, name, proxy_session)
        except LogMissingError as e:
            raise AssemblyError(f"{cid}: {e}. Check state_dir") from None
        if resolved.binding is not None:
            if text is not None and text != resolved.text:
                raise AssemblyError(f"{cid}: text= differs from the approved rendering the model will receive")
            text = resolved.text
        elif text is None:
            raise AssemblyError(f"{cid}: not bound ({resolved.cause}). "
                                "Pass text= with the exact bytes the model receives")
        method = "tool_definition" if kind == "tool" else "server_instructions"
        self._component(cid, method, text, 0, position, None, server_id=server_id, name=name,
                        session=proxy_session, resolved=resolved)

    def server_instructions(self, cid: str, *, server_id: str, proxy_session, text: str | None = None) -> None:
        self._bound(cid, "instructions", server_id, None, proxy_session, text)

    def tool_definition(self, cid: str, *, server_id: str, name: str, proxy_session,
                        text: str | None = None) -> None:
        if not isinstance(name, str) or not name:
            raise AssemblyError(f"{cid}: name is required")
        self._bound(cid, "tool", server_id, name, proxy_session, text)

    def observe_session(self, server_id: str, proxy_session) -> None:
        """Register a server's live proxy session without assembling anything from it (spec 9.2).

        _blocked() otherwise only reads the logs of sessions some assembled
        component names. An application that assembles nothing from a server
        whose only tool the proxy blocked would then emit a record with no
        trace of the block. Registering the session here makes emit() read
        that log too, under the same header check. proxy_session=None (no
        proxy in front of the server) registers nothing, so the call is safe
        to make unconditionally after every list result.
        """
        self._check_server(server_id)
        if proxy_session is None:
            return
        if not isinstance(proxy_session, ProxySession):
            raise AssemblyError("observe_session: proxy_session must come from session_from_meta or be None")
        if not self.verifier.log_path(server_id, proxy_session).exists():
            raise AssemblyError("observe_session: the attestation log for this proxy session does not exist. "
                                "Check state_dir")
        self._observed.setdefault((server_id, proxy_session.proxy_session_id), proxy_session)

    def token_ids(self) -> list[int]:
        """BOS plus the concatenated per-part ids.

        Every part already passed the marker-adjacency self-check in
        _append() when it was appended (a refused part never entered
        self._parts), so this only concatenates what is already known good.
        """
        return list(self.tok.bos_ids) + [i for part in self._parts for i in part.ids]

    def text(self) -> str:
        """The assembled text without BOS, for audits and whole-string equality checks.

        A part appended by model_output_ids contributes the decoding of its
        ids. Its ids are the model's own, so re-encoding this text is not
        guaranteed to give token_ids() back across that part, and that is the
        point of appending ids rather than text.
        """
        return "".join(p.text for p in self._parts)

    def _scan(self, comp: _Component, ctype: str) -> ScanResult | None:
        if self.scanner is None:
            return None
        try:
            res = self.scanner(ctype, comp.text)
        except Exception:
            # The scanner is caller-supplied code running inside emit(). Its own
            # exception text could carry anything, including the component text
            # it was scanning, so it is never echoed. AssemblyError is the one
            # failure shape emit() promises to raise.
            raise AssemblyError("scanner failed") from None
        if not isinstance(res, ScanResult) or res.status not in _SCAN_STATUS or \
                res.injection_risk_rating not in _RATINGS or \
                not all(isinstance(v, bool) for v in (res.contains_pii, res.contains_credentials,
                                                       res.contains_secrets_or_keys)):
            raise AssemblyError(f"{comp.cid}: scanner must return a complete ScanResult")
        try:
            parse_time(res.scanned_at)
        except ValueError:
            raise AssemblyError(f"{comp.cid}: scanner scanned_at is not RFC 3339") from None
        return res

    def _unbound_uri(self, comp: _Component) -> str:
        """The attestation reference for an unbound item whose proxy session is known.

        "cxbom-attest:<session>#<seq>" names the latest line the proxy wrote
        about this item (its newest verdict for a tool, its newest server
        line for instructions), so a reader can find why it did not bind. A
        log that is missing, unreadable, or whose header names another
        session or server yields no seq, and the reference stays at the
        session. With no session there is nothing to reference.
        """
        if comp.session is None:
            return ""
        psid = comp.session.proxy_session_id
        try:
            lines, _states = self.verifier.read_state(self.verifier.log_path(comp.server_id, comp.session))
        except LogMissingError:
            lines = None
        seqs: list[int] = []
        if lines is not None and lines[0]["proxySessionId"] == psid and lines[0]["serverId"] == comp.server_id:
            if comp.method == "tool_definition":
                seqs = [x["seq"] for x in lines if x.get("kind") == "verdict" and x.get("itemType") == "tool"
                        and x.get("name") == comp.name]
            else:
                seqs = [x["seq"] for x in lines if x.get("kind") == "server"]
        return f"cxbom-attest:{psid}#{seqs[-1]}" if seqs else f"cxbom-attest:{psid}"

    def _tool_facts(self, comp: _Component) -> dict:
        r = comp.resolved
        entry = r.entry
        first_party = bool(entry and entry["firstParty"])
        cause = r.cause
        if r.binding is not None:
            try:
                cause = self.verifier.recheck(r.binding)
            except LogMissingError as e:
                raise AssemblyError(f"{comp.cid}: {e}. Check state_dir") from None
        source = {"origin": "mcp-server", "thirdParty": not first_party, "operatorControlled": first_party,
                  "serverVersionPinned": version_pinned(entry)}
        b = r.binding
        if b is not None and not cause:
            fp16 = b.fingerprint[:16]
            who = f"{b.approved_by}:{b.approval_mode}" if b.kind == "tool" else "none:signed-entry"
            source.update(serverChecksumVerified=True, serverChecksum=b.sha256, sessionId=b.proxy_session_id,
                          uri=f"cxbom-attest:{b.proxy_session_id}#{b.seq}", retrievedAt=b.at,
                          authorizedBy=f"unverified-approver:{who}:signer-{fp16}")
            if b.server_version is not None:
                source["serverVersion"] = b.server_version
            uri = source["uri"]
        else:
            source["serverChecksumVerified"] = False
            uri = self._unbound_uri(comp)
            if uri:
                source["uri"] = uri
        # _blocked() redacts a blocked name through the same function, so an
        # assembled label and a blocked finding's name still pair up for
        # consistency.check's "blocked never also assembled" rule.
        label = f"mcp-tool:{comp.server_id}/{_safe_server_string(comp.name)}" \
            if comp.method == "tool_definition" else \
            f"mcp-instructions:{comp.server_id}"
        return {"subtype": "internal-operator-authored" if first_party else "external-mcp-server",
                "source": source, "label": label, "verified": b is not None and not cause,
                "changed": r.verdict == "changed", "cause": cause or "", "uri": uri}

    def _facts(self, comp: _Component) -> ComponentFacts:
        base = dict(cid=comp.cid, turn=comp.turn, position=comp.position,
                    text_sha256=hashlib.sha256(comp.text.encode("utf-8")).hexdigest(), token_count=len(comp.ids),
                    special_role=comp.special_role, special_other=comp.special_other,
                    role_spelled=comp.role_spelled, other_spelled=comp.other_spelled)
        m = comp.method
        if m == "system_prompt":
            spec = dict(type="system-prompt", subtype="primary-operator-instruction", ring=0, tier="operator",
                        layer="system-prompt", label="Operator system prompt", by_type="systemPrompt",
                        source={"origin": "operator", "thirdParty": False, "operatorControlled": True})
        elif m == "user_turn":
            spec = dict(type="user-turn", subtype="conversational-query", ring=2, tier="user", layer="ingress",
                        label=f"User turn {comp.turn}", by_type="userTurn",
                        source={"origin": "user", "thirdParty": False})
        elif m == "model_output":
            spec = dict(type="retrieved-document", subtype="memory-injection", ring=1, tier="ring-1-derived",
                        layer="reasoning", label=f"Model output, turn {comp.turn}", by_type="modelOutput",
                        source={"origin": "model-generated", "thirdParty": False})
        elif m == "retrieved_document":
            spec = dict(type="retrieved-document", subtype="rag-chunk", ring=1, tier="agent", layer="tool-execution",
                        label=f"Retrieved document ({comp.origin})", by_type="retrievedDocument",
                        source={"origin": comp.origin, "uri": comp.uri, "thirdParty": True})
        elif m == "tool_result":
            ve, _cause = self.verifier.entry(comp.server_id)
            first_party = bool(ve and ve.entry["firstParty"])
            tool_id = f"{comp.server_id}/{_safe_server_string(comp.name)}"
            spec = dict(type="tool-result", subtype="external-api-response", ring=1, tier="agent",
                        layer="tool-execution", label=f"mcp-tool-result:{tool_id}",
                        by_type="toolResult",
                        source={"origin": "mcp-tool-result", "toolId": tool_id,
                                "thirdParty": not first_party, "serverChecksumVerified": False})
        else:
            t = self._tool_facts(comp)
            spec = dict(type="tool-definition", subtype=t["subtype"], ring=1, tier="agent", layer="tool-execution",
                        label=t["label"], by_type="toolDefinition", source=t["source"], is_tool=True,
                        verified=t["verified"], changed=t["changed"], unbound_cause=t["cause"], source_uri=t["uri"])
        facts = ComponentFacts(**base, **spec)
        scan = self._scan(comp, facts.type)
        return ComponentFacts(**{**asdict(facts), "scan": scan}) if scan is not None else facts

    def _blocked(self) -> list[BlockedItem]:
        assembled = {(c.server_id, c.name) for c in self._components if c.method == "tool_definition"}
        # Sessions named by assembled components come first, then sessions only
        # observed, so finding order stays stable for callers that never observe.
        sessions: dict[tuple[str, str], tuple[ProxySession, str]] = {}
        for comp in self._components:
            if comp.session is not None and comp.resolved is not None:
                sessions.setdefault((comp.server_id, comp.session.proxy_session_id), (comp.session, comp.cid))
        for (sid, psid), session in self._observed.items():
            sessions.setdefault((sid, psid), (session, f"observe_session({sid!r})"))
        seen: dict[tuple[str, str], BlockedItem] = {}
        for (sid, psid), (session, where) in sessions.items():
            try:
                lines, states = self.verifier.read_state(self.verifier.log_path(sid, session))
            except LogMissingError as e:
                raise AssemblyError(f"{where}: {e}. Check state_dir") from None
            if lines is None:
                continue
            head = lines[0]
            # Only an enforce-mode proxy withholds a blocked tool from the client.
            # In observe mode the tool still reaches the application, so a
            # "blocked" state there is not a mitigation the record may claim.
            if head["mode"] != "enforce":
                continue
            # The file name is not proof of whose session or server this log
            # belongs to (a same-user hard link, or a swapped file under the
            # expected name, can put a different session's log where this
            # name is looked up), the same threat Verifier.resolve and
            # Verifier.recheck already guard against for a bound item (Task
            # 10 ruling minor 5).
            if head["proxySessionId"] != psid or head["serverId"] != sid:
                continue
            for (item_type, name), item in states.items():
                if item_type == "tool" and item.state == BLOCKED and (sid, name) not in assembled:
                    why = item.verdict if item.verdict not in (None, PINNED_MATCH) else item.cause
                    seen[(sid, name)] = BlockedItem(sid, _safe_server_string(name), why,
                                                    f"cxbom-attest:{psid}#{item.seq}")
        return list(seen.values())

    def _stop_note(self, stop: int | None) -> str:
        """How a generation ended, for the content.sha256 glossary entry."""
        if stop is None:
            return "cut off before any stop id"
        eog = f"{self._eog} {self._special_by_id[self._eog]}"
        if stop == self._eog:
            return f"stopped on {eog}"
        # A numeric-id stop has no _special_by_id entry (it is neither added nor
        # flagged special), so name it by the text the pinned tokenizer renders.
        name = self._special_by_id[stop] if stop in self._special_by_id else self.tok.decode([stop])
        return f"stopped on {stop} {name}, turn closed by the template with {eog}"

    def _glossary(self, ids: list[int]) -> dict:
        g = dict(GLOSSARY_FIXED)
        g["content.tokenCount"] = (
            f"tokenizer sha256 {self.tok.sha256}, tokenizers {self.tok.library_version}, mode ids, "
            f"serving {self.serving}, id-sequence sha256 {ids_sha256(ids)}, split tokens 0")
        generated = [f"{c.cid}={c.generated_ids_sha256} {self._stop_note(c.generated_stop)}"
                     for c in self._components if c.generated_ids_sha256 is not None]
        if generated:
            g["content.sha256"] = (
                "SHA-256 of the component's UTF-8 text. Model output appended from generated ids carries the text "
                "those ids decode to, and the ids are its provenance. Generated-ids sha256 (RFC 8785 array of the "
                "ids exactly as passed, a terminal stop id included when present) and the stop id that ended "
                "the generation, per component. " + "; ".join(generated))
        g["metadata.session.model"] = (
            f"revision {self.model.revision}, template family {self.table.family}, "
            f"chat_template sha256 {self.table.chat_template_sha256}")
        return g

    def emit(self, *, session_id: str, turn: int, inference_index: int, sent_ids_sha256: str) -> dict:
        if not isinstance(session_id, str) or not _SESSION.fullmatch(session_id):
            raise AssemblyError("session_id must be 1 to 128 of [A-Za-z0-9_.:-]")
        for label, value in (("turn", turn), ("inference_index", inference_index)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise AssemblyError(f"{label} must be a non-negative integer")
        if not self._components:
            raise AssemblyError("nothing assembled")
        ids = self.token_ids()
        if len(ids) > self.model.context_window_max:
            raise AssemblyError(f"{len(ids)} tokens exceed the model's {self.model.context_window_max}-token window")
        if not isinstance(sent_ids_sha256, str) or not _HEX64.fullmatch(sent_ids_sha256) or \
                sent_ids_sha256 != ids_sha256(ids):
            raise AssemblyError("sent_ids_sha256 does not match ids_sha256(asm.token_ids())")
        comps = [self._facts(c) for c in self._components]
        m = self.model
        inputs = RecordInputs(
            session_id=session_id, turn=turn, inference_index=inference_index,
            model={"family": m.family, "version": m.version, "provider": m.provider,
                   "contextWindowMaxTokens": m.context_window_max, "architectureType": m.architecture_type},
            agent={"id": self.agent.id, "name": self.agent.name, "version": self.agent.version,
                   "operator": self.agent.operator, "deploymentEnvironment": self.agent.environment,
                   "deploymentId": self.agent.deployment_id},
            trust_model=self.trust_model.as_record(),
            control_layers=[layer.as_record() for layer in self.control_layers],
            components=comps, overhead_tokens=len(ids) - sum(c.token_count for c in comps),
            context_window_max=m.context_window_max, glossary=self._glossary(ids), blocked=self._blocked())
        record = build_record(inputs, now_rfc3339())
        errors = conformance.check_all(record) + consistency.check(record)
        errors += consistency.anonymity(record, str(_account(paths.pw_dir)))
        if errors:
            raise AssemblyError("record failed validation: " + "; ".join(errors[:5]))
        return record


def c2_events(record: dict, record_path: str) -> list[dict]:
    """C2 1.1.0 emitter events for one record, as {type, data} pairs in context order.

    The J2 collector is the merged stream's single writer, so it adds v, seq, t,
    run and prev_sha256. record_path must be relative, because events are
    published and the anonymity rule forbids local paths.
    """
    if not isinstance(record_path, str) or not record_path or record_path.startswith(("/", "~")) or \
            ".." in Path(record_path).parts or "\\" in record_path or ":" in record_path:
        raise AssemblyError("record_path must be a relative path inside the run directory")
    comps = record["contextComponents"]
    events = [{"type": "component_assembled",
               "data": {"componentId": c["id"], "type": c["type"], "ring": c["trustRing"],
                        "tokens": c["content"]["tokenCount"], "sourceOrigin": c["source"]["origin"],
                        "position": i}} for i, c in enumerate(comps)]
    events.append({"type": "cxbom_emitted", "data": {
        "recordPath": record_path, "findingsOpen": record["sessionSummary"]["findingsSummary"]["totalOpen"],
        "inversionDetected": any(c.get("toolDefinitionTrustInversion", {}).get("detected") is True for c in comps)}})
    return events
