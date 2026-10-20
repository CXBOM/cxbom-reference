"""Closed renderer registry for approved tool definitions (spec 9.2).

Owner: ATACE Working Group.

The signed lock entry names the renderer, and the emitter renders the stored
wire object through it, so the model sees text derived from exactly the
attested object. This build registers jcs only. json-indent2 and wire land
with the Oct 10 slice. An entry naming a renderer outside the registry makes
the definition unrenderable here, and the caller's text is recorded as
unverified instead.

check_rendered proves the rendered text parses back (strictly) to the stored
object and still hashes to the signed pin. It compares canonical bytes, not
Python equality, because True == 1 in Python while RFC 8785 keeps them apart.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Callable, Mapping, Sequence

from . import jsonstrict
from .canonical import CanonicalizationError, IgnoredFieldError, canonical, tool_sha256


class RendererError(ValueError):
    """A renderer is unknown, or the rendered text does not match the attested object."""


def _jcs(obj) -> str:
    return canonical(obj).decode("utf-8")


RENDERERS: Mapping[str, Callable[[object], str]] = MappingProxyType({"jcs": _jcs})


def render(name: str, obj) -> str:
    fn = RENDERERS.get(name)
    if fn is None:
        raise RendererError(f"renderer {name!r} is not in this build's registry {sorted(RENDERERS)}")
    try:
        return fn(obj)
    except CanonicalizationError as e:
        raise RendererError(f"cannot render with {name}: {e}") from None


def check_rendered(text: str, obj, ignore: Sequence[str], pin_sha256: str) -> None:
    try:
        parsed = jsonstrict.to_python(jsonstrict.parse(text.encode("utf-8")))
    except (jsonstrict.StrictJSONError, UnicodeError) as e:
        raise RendererError(f"rendered text is not strict JSON: {e}") from None
    try:
        same = canonical(parsed) == canonical(obj)
        pinned = tool_sha256(parsed, ignore) == pin_sha256
    except (CanonicalizationError, IgnoredFieldError) as e:
        raise RendererError(f"rendered text cannot be re-hashed: {e}") from None
    if not same:
        raise RendererError("rendered text does not parse back to the attested object")
    if not pinned:
        raise RendererError("rendered text does not hash to the signed pin")
