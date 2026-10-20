"""Load a GitHub Actions workflow the way GitHub would refuse it, as far as a test can.

Owner: ATACE Working Group.

`yaml.safe_load` is not GitHub's validator. It accepts two things GitHub
either rejects or reads differently, and both have a cost here:

- A duplicate key. PyYAML keeps the last value silently, so a second `run:`
  under the step that runs `anon_check.py range` would replace the check with
  whatever follows and every test reading the parsed file would still pass.
- A key GitHub does not know. `run-on:` for `runs-on:` parses as an ordinary
  mapping, and GitHub rejects the workflow before any job starts, the same way
  it rejected the unquoted `:all:` that left CI red on main in 0 s.

This loader refuses both. It does not replace a real workflow linter: an
expression error, a bad `needs` reference or a wrong value type still passes.
"""
from __future__ import annotations

from pathlib import Path

import yaml

# The keys GitHub documents for each level of a workflow. Closed on purpose: a
# key outside these is a typo or a feature this repository has not reviewed.
WORKFLOW_KEYS = frozenset({"name", "run-name", "on", "permissions", "env", "defaults",
                           "concurrency", "jobs"})
JOB_KEYS = frozenset({"name", "permissions", "needs", "if", "runs-on", "snapshot",
                      "environment", "concurrency", "outputs", "env", "defaults", "steps",
                      "timeout-minutes", "strategy", "continue-on-error", "container",
                      "services", "uses", "with", "secrets"})
STEP_KEYS = frozenset({"id", "if", "name", "uses", "run", "working-directory", "shell",
                       "with", "env", "continue-on-error", "timeout-minutes"})


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that raises on a key repeated within one mapping."""


def _unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def load_workflow(path: Path) -> dict:
    """The parsed workflow, after refusing duplicate keys and keys GitHub does not know.

    YAML 1.1 reads the bare key `on` as the boolean true, so the top level maps
    it back before the key check rather than accepting any boolean key.
    """
    document = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)  # noqa: S506
    assert isinstance(document, dict), f"{path.name} does not load to a mapping"
    if True in document:
        document["on"] = document.pop(True)
    unknown = set(document) - WORKFLOW_KEYS
    assert not unknown, f"{path.name}: top-level keys GitHub does not know: {sorted(unknown)}"
    assert isinstance(document.get("jobs"), dict) and document["jobs"], f"{path.name}: no jobs"
    for job_id, job in document["jobs"].items():
        assert isinstance(job, dict), f"{path.name}: job {job_id} is not a mapping"
        unknown = set(job) - JOB_KEYS
        assert not unknown, f"{path.name}: job {job_id} has keys GitHub does not know: {sorted(unknown)}"
        assert "runs-on" in job or "uses" in job, f"{path.name}: job {job_id} has no runs-on"
        for index, step in enumerate(job.get("steps", [])):
            assert isinstance(step, dict), f"{path.name}: {job_id} step {index} is not a mapping"
            unknown = set(step) - STEP_KEYS
            assert not unknown, (
                f"{path.name}: {job_id} step {index} has keys GitHub does not know: {sorted(unknown)}")
            assert ("run" in step) != ("uses" in step), (
                f"{path.name}: {job_id} step {index} needs exactly one of run and uses")
    return document
