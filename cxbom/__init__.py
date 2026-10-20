"""cxbom: MCP pinning proxy and CxBOM emitter. Owner: ATACE Working Group."""
__version__ = "0.3.0.dev0"

# The vendored validator and crosswalk build filesystem paths from
# str(importlib.resources.files("cxbom")), and they stay identical to ATACE
# except their declared hunks (spec 3, spec/published.lock.json, and section 4
# of docs/design/tool.md). Imported from a zip archive that path does not
# exist, and the first emit would fail deep inside the validator. Refuse at
# import instead, with the one fix that works (spec 12).
# A custom importer can also report a Path that does not exist, so the check
# requires a real directory, not only the Path type.
from importlib import resources as _resources  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

_root = _resources.files(__name__)
if not (isinstance(_root, _Path) and _root.is_dir()):
    raise ImportError("cxbom must be installed as files on disk (pip install the wheel). "
                      "It cannot run from a zip archive")
del _root

# jsonschema skips "date-time" silently when its optional extra is not
# installed, so every timestamp check would pass unchecked. attestation.py and
# lockfile.py refuse that at their own import, and the eager API imports below
# used to reach them on any package import. With the API resolved lazily,
# nothing did on the `python -m cxbom.validator` path, which then printed OK
# for a record whose timestamp is not a date-time. Refuse here, at package
# import, so every entry point fails closed. jsonschema is a core dependency.
from jsonschema import FormatChecker as _FormatChecker  # noqa: E402

_missing = [f for f in ("date-time", "uuid") if f not in _FormatChecker().checkers]
if _missing:
    # An ImportError that names this package: runpy turns one raised by a
    # package import into a single stderr line under `python -m`, where any
    # other exception, or an ImportError without the name, is a traceback.
    raise ImportError(f"jsonschema FormatChecker lacks {', '.join(_missing)}. Install the pins in "
                      "pyproject.toml: jsonschema[format-nongpl] and rfc3339-validator, which provides date-time",
                      name=__name__)
del _missing, _FormatChecker

# The emitter API (spec 9.2), resolved on first access rather than at import.
# Importing these eagerly loaded cxbom.assembly, and through it cxbom.validator,
# whenever anything imported the package. `python -m cxbom.validator` imports
# the package first, so runpy then found the module it was about to run already
# in sys.modules and wrote a RuntimeWarning to stderr on every invocation: a
# second stderr line under the CLI's one-line refusal (owner ruling 2).
# `from cxbom import Assembly` and `cxbom.Assembly` still work unchanged.
_API = {
    "AgentInfo": "assembly", "Assembly": "assembly", "AssemblyError": "assembly", "ControlLayer": "assembly",
    "ModelInfo": "assembly", "TrustModel": "assembly", "c2_events": "assembly", "ids_sha256": "assembly",
    "BindingError": "binding", "session_from_meta": "binding",
    "ScanResult": "emitter",
    "TokenizerError": "tokenizer", "load_tokenizer": "tokenizer",
}

__all__ = ["AgentInfo", "Assembly", "AssemblyError", "BindingError", "ControlLayer", "ModelInfo", "ScanResult",
           "TokenizerError", "TrustModel", "c2_events", "ids_sha256", "load_tokenizer", "session_from_meta"]


def _submodules() -> set[str]:
    from pkgutil import iter_modules
    return {m.name for m in iter_modules(__path__) if not m.name.startswith("__")}


def __getattr__(name: str):
    """A public API name, or a submodule by its own name.

    The eager imports this replaces also bound every submodule they loaded as
    an attribute of the package, so `import cxbom` then `cxbom.assembly` worked,
    and callers rely on it (lab/j1/tests/test_assembly_equivalence.py reads
    cxbom.assembly.Assembly after `pytest.importorskip("cxbom")`). A submodule
    is imported here on first access instead, which keeps that contract without
    loading anything at package import.
    """
    from importlib import import_module
    module = _API.get(name)
    if module is not None:
        value = getattr(import_module(f".{module}", __name__), name)
        globals()[name] = value  # later lookups skip this function
        return value
    if name in _submodules():  # never __main__, which _submodules leaves out: importing it runs the CLI
        return import_module(f".{name}", __name__)  # the import binds it on the package too
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | set(__all__) | _submodules())
