"""The emitter's public surface and its C2 events (spec 9.2, contracts C2 1.1.0).

Owner: ATACE Working Group.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from conftest import emit, new_assembly

ROOT = Path(__file__).resolve().parents[1]


def test_spec_import_line_works():
    from cxbom import (AgentInfo, Assembly, ControlLayer, ModelInfo, TrustModel, load_tokenizer,
                       session_from_meta)
    assert all(callable(x) for x in (AgentInfo, Assembly, ControlLayer, ModelInfo, load_tokenizer,
                                     session_from_meta))
    assert TrustModel.three_ring().as_record()["rings"][1]["designation"] == "agent"


def test_every_public_name_resolves_and_the_package_import_loads_none_of_them():
    """cxbom/__init__.py resolves its API on first access. Importing the package
    alone must not load cxbom.validator, or `python -m cxbom.validator` writes a
    runpy RuntimeWarning to stderr, and every name in __all__ must still resolve."""
    code = ("import sys, cxbom\n"
            "loaded = sorted(m for m in ('cxbom.assembly', 'cxbom.validator', 'cxbom.binding', 'cxbom.emitter')\n"
            "                if m in sys.modules)\n"
            "missing = [n for n in cxbom.__all__ if getattr(cxbom, n, None) is None]\n"
            "print(loaded, missing)")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[] []"


# Blocks the module jsonschema's "date-time" checker needs, which is what an
# install without jsonschema's date-time support looks like from the inside.
_NO_DATE_TIME = "import sys\nsys.modules['rfc3339_validator'] = None\n"


def test_the_date_time_format_check_fires_at_package_import():
    """Where the refusal of a jsonschema without date-time fires. It used to be
    a side effect of the eager API imports reaching attestation.py. With the API
    resolved lazily it has to be the package import itself, or an entry point
    that loads no API module (python -m cxbom.validator) runs without it."""
    code = _NO_DATE_TIME + "import cxbom\nprint('imported')\n"
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert r.returncode == 1
    assert r.stdout == ""
    assert r.stderr.splitlines()[-1] == (
        "ImportError: jsonschema FormatChecker lacks date-time. Install the pins in pyproject.toml: "
        "jsonschema[format-nongpl] and rfc3339-validator, which provides date-time")


def test_a_bare_package_import_still_reaches_every_submodule_by_attribute():
    """The eager API imports used to bind every submodule they loaded on the
    package, and callers rely on it: lab/j1/tests/test_assembly_equivalence.py
    reads cxbom.assembly.Assembly._append after pytest.importorskip("cxbom").
    Each submodule attribute must resolve after a bare import and nothing
    else, and the import itself must still load none of them."""
    code = ("import inspect, pkgutil, sys\n"
            "import cxbom\n"
            "assert [m for m in sys.modules if m.startswith('cxbom.')] == []\n"
            "names = sorted(m.name for m in pkgutil.iter_modules(cxbom.__path__) if not m.name.startswith('__'))\n"
            "wrong = [n for n in names if getattr(cxbom, n) is not sys.modules['cxbom.' + n]]\n"
            "print(len(names), wrong, list(inspect.signature(cxbom.assembly.Assembly._append).parameters))\n"
            "print(hasattr(cxbom, 'no_such_module'), 'validator' in dir(cxbom), 'Assembly' in dir(cxbom))\n")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
    count, rest = out.stdout.split(" ", 1)
    assert int(count) >= 25
    assert rest.splitlines() == ["[] ['self', 'kind', 'text', 'label']", "False True True"]


def test_cxbom_main_is_never_reachable_through_the_package():
    """Importing cxbom.__main__ runs the CLI. __getattr__ reaches only names
    _submodules() lists, and _submodules() leaves out every dunder name, so
    neither dir(), getattr(), inspect.getmembers() nor help() can import it.
    Without that filter, getmembers exited the process with status 2 and the
    CLI's usage error."""
    code = ("import inspect, io, pydoc, sys, contextlib\n"
            "import cxbom\n"
            "assert '__main__' not in dir(cxbom)\n"
            "try:\n"
            "    cxbom.__main__\n"
            "    raise SystemExit('reachable')\n"
            "except AttributeError:\n"
            "    pass\n"
            "inspect.getmembers(cxbom)\n"
            "pydoc.render_doc(cxbom)\n"
            "with contextlib.redirect_stdout(io.StringIO()):\n"
            "    help(cxbom)\n"
            "print('cxbom.__main__' in sys.modules)\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=120,
                       env={**os.environ, "PAGER": "cat", "MANPAGER": "cat"})
    assert (r.returncode, r.stdout, r.stderr) == (0, "False\n", "")


def test_dir_lists_submodules_before_they_load():
    code = "import cxbom\nprint(sorted({'assembly', 'validator', 'crosswalk', 'Assembly'} - set(dir(cxbom))))"
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


def test_core_import_does_not_load_tokenizers():
    # tokenizers is the cxbom[emit] extra. The proxy imports cxbom without it.
    code = "import sys, cxbom; print('tokenizers' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"


def test_c2_events_match_the_frozen_event_schema(phi3, tmp_path, make_world):
    from cxbom import AssemblyError, c2_events
    schema = json.loads((ROOT / "contracts/events/event.schema.json").read_text(encoding="utf-8"))
    check = Draft202012Validator(schema, format_checker=FormatChecker())
    w = make_world()
    asm = new_assembly(phi3, tmp_path, world=w)
    asm.marker("system")
    asm.system_prompt("cc-001", text="You are a research assistant.")
    asm.sep("\n")
    asm.tool_definition("cc-002", server_id="fetch", name="fetch", proxy_session=w.session)
    asm.marker("end")
    record = emit(asm)
    events = c2_events(record, "records/take3-0001.cxbom.json")
    assert [e["type"] for e in events] == ["component_assembled", "component_assembled", "cxbom_emitted"]
    assert events[1]["data"] == {"componentId": "cc-002", "type": "tool-definition", "ring": 1,
                                 "tokens": record["contextComponents"][1]["content"]["tokenCount"],
                                 "sourceOrigin": "mcp-server", "position": 1}
    assert events[2]["data"]["inversionDetected"] is True
    for seq, e in enumerate(events):
        line = {"v": 1, "seq": seq, "t": float(seq), "run": "take3",
                "prev_sha256": None if seq == 0 else "0" * 64, **e}
        assert list(check.iter_errors(line)) == []
    for bad in ("/tmp/r.json", "../r.json", "~/r.json", ""):
        with pytest.raises(AssemblyError, match="relative path"):
            c2_events(record, bad)


def test_c2_events_refuse_a_drive_or_scheme_path():
    import pytest
    from cxbom import AssemblyError, c2_events
    for bad in ("C:/runs/r.json", "file:r.json"):
        with pytest.raises(AssemblyError):
            c2_events({}, bad)


def test_error_types_are_exported():
    """Final review minor 3: a caller catches these without reaching into submodules."""
    import cxbom
    from cxbom.binding import BindingError
    from cxbom.tokenizer import TokenizerError
    assert cxbom.BindingError is BindingError and cxbom.TokenizerError is TokenizerError
    assert {"BindingError", "TokenizerError"} <= set(cxbom.__all__)
