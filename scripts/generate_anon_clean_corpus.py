"""Seeded, synthetic clean-text corpus for demo/anon.py's zero-false-positive claim.

Owner: ATACE Working Group.

Round 2 and round 3 of Task 5 measured "zero false positives" against two
clean corpora (3,000 flat lines, 3,000 pane-width lines) that were built by an
ad-hoc script, run once, and discarded. Neither corpus nor the script that made
it was ever committed, so the claim could not be checked from the repository
alone -- round 4's reviewer named this a standing gap. This script closes it:
every line is generated from a fixed seed and a template bank checked into
this file, so `--check` reproduces the same corpus and the same scan result on
any machine, indefinitely, without ever writing the corpus itself to disk.

Every template is synthetic. None names a real host beyond `cxbom.org` (the
project's own allowed domain) and the RFC 2606/6761 reserved names `.test`,
`.example`, `.invalid`, `.localhost` that `demo/anon.py` itself allowlists.
No line contains a denylisted term, a real key, or a real voice id -- there is
nothing here for `anon_check.py` to catch, which is itself part of what
`--check` demonstrates.

The template bank deliberately includes the sentence shapes that are most
likely to be misread by the rejoin pass: a sentence ending in ". " followed by
a word that is also a public or local-network suffix ("Then restart. local
changes apply", "build ok. dev mode off", "tool label. co ordinates"), a float
table, and an email-shaped mention of the project's own allowed domain. These
are exactly the lines demo/anon.py's own module report (Task 5, round 2)
named as the ones a naive rejoin turns into false host-name findings.

Usage:
    python scripts/generate_anon_clean_corpus.py --check           # scan and report
    python scripts/generate_anon_clean_corpus.py --check --seed 7  # a different draw
    python scripts/generate_anon_clean_corpus.py --print flat      # inspect the lines
    python scripts/generate_anon_clean_corpus.py --print pane      # ...pane-wrapped
Exit 0 when --check finds zero findings across both corpora, 1 otherwise.
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import Iterator

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

DEFAULT_SEED = 20260927  # the date this generator was written, not a per-run value
DEFAULT_COUNT = 3000
PANE_WIDTH = 80  # a narrow terminal pane column count, chosen to force mid-token wraps

# Filler word bank: short, lowercase, alphanumeric-only, so substituting one
# into a template can never accidentally complete a shape (no dots, no "@",
# no digit-heavy run that could look like an IP octet).
_WORDS = (
    "queue", "frame", "node", "batch", "delta", "window", "buffer", "signal",
    "trace", "slot", "phase", "run", "step", "check", "sweep", "lane", "gate",
    "pass", "shard", "cell",
)

# One template per line. "{n}" is an int filler, "{f}" a float filler, "{w}" a
# word filler. Every template renders to text with no IP, email, host, path,
# key, or voice-id shape once filled -- confirmed by --check, not asserted
# here, since the point of this file is a reproducible measurement rather
# than a duplicate of demo/anon.py's own patterns.
_TEMPLATES = (
    "Then restart. local changes apply to {w} {n}.",
    "Build ok. dev mode off for {w} {n}.",
    "Frame {n} captured, tool label. co ordinates recorded at {f}.",
    "Value delta {f} over {f} seconds for {w}, within tolerance.",
    "mail ops at example.org handles the {w} inbox.",
    "See docs at inbox.test for the double-blind contact on {w} {n}.",
    "Session {n} complete after {n} retries. all clear on {w}.",
    "Node {w} answered in {f} ms. no timeout observed.",
    "Everything nominal on {w}. next window opens in {n} s.",
    "Report queued. batch {n} of {n} pending for {w}.",
    "Reach the queue at cxbom.org support for {w} {n}.",
    "The attacker inbox is inbox.test, referenced from {w} {n}.",
    "Sensor {w} read {f}, {f}, {f} across three passes.",
    "Retry {n} of {n} for {w} finished. no action needed.",
    "Closing {w} lane after {n} clean sweeps at {f} each.",
    "Nothing to redact on {w} {n}; frame stays as recorded.",
    "The {w} gate opened at step {n}. next check in {f} s.",
    "Handoff to {w} complete. sequence {n} archived.",
    "Table row {n}: {f} {f} {f} {f} -- all within band.",
    "End of {w} run {n}. summary follows on the next line.",
)


def _fill(template: str, rng: random.Random) -> str:
    return template.format(
        n=rng.randint(0, 999),
        f=round(rng.uniform(0.0, 999.0), 3),
        w=rng.choice(_WORDS),
    )


def flat_lines(count: int = DEFAULT_COUNT, seed: int = DEFAULT_SEED) -> list[str]:
    """`count` clean lines, one sentence each, no hard wrap."""
    rng = random.Random(seed)
    return [_fill(rng.choice(_TEMPLATES), rng) for _ in range(count)]


def _wrap_at(text: str, width: int) -> str:
    """Hard-wrap `text` at `width` columns, joining with a plain space.

    A real pane wraps mid-token as often as at a word boundary, so the break
    is inserted at a fixed column count rather than the nearest space -- the
    same mid-token wrap _normalize()'s docstring exists to undo. Joining the
    pieces with U+0020 simulates the innerText()-style extractor that renders
    a soft wrap as the same character that separates words everywhere else,
    which is the harder case for the rejoin pass, not the easier one.
    """
    pieces = [text[i:i + width] for i in range(0, len(text), width)]
    return " ".join(pieces)


def pane_lines(count: int = DEFAULT_COUNT, seed: int = DEFAULT_SEED,
               width: int = PANE_WIDTH, sentences_per_row: int = 4) -> list[str]:
    """`sentences_per_row` clean sentences concatenated, then hard-wrapped to `width` columns.

    A single short sentence rarely exceeds a terminal's column count, so
    wrapping it alone would almost never land mid-token and this corpus would
    just reproduce `flat_lines()`. Concatenating several sentences per row --
    the way a scrolled pane actually reads -- makes a wrap point, and the
    mid-token cut it can produce, the common case rather than a rare one,
    which is the scale round 2's 662,376-byte pane corpus was actually built
    at (about 220 bytes a row across 3,000 rows).
    """
    rng = random.Random(seed + 1)  # distinct stream from flat_lines' own draw
    out = []
    for _ in range(count):
        row = " ".join(_fill(rng.choice(_TEMPLATES), rng) for _ in range(sentences_per_row))
        out.append(_wrap_at(row, width))
    return out


def _iter_corpora(seed: int, count: int) -> Iterator[tuple[str, list[str]]]:
    yield "flat", flat_lines(count, seed)
    yield "pane", pane_lines(count, seed)


def check(seed: int = DEFAULT_SEED, count: int = DEFAULT_COUNT) -> int:
    """Scan both corpora and report finding counts. Returns a process exit code."""
    from demo import anon

    tokens = ["redacted-person", "redacted-lab"]  # synthetic; never the real denylist
    total_findings = 0
    for label, lines in _iter_corpora(seed, count):
        flagged = 0
        kinds: dict[str, int] = {}
        for i, line in enumerate(lines):
            errs = anon.scan(f"{label}[{i}]", line, tokens)
            if errs:
                flagged += 1
                for e in errs:
                    # Bucket by the static finding text after the name, never
                    # by matched content -- scan() itself never echoes that.
                    kind = e.split(": ", 1)[1] if ": " in e else e
                    kinds[kind] = kinds.get(kind, 0) + 1
        total_findings += flagged
        print(f"{label}: {len(lines)} lines, {flagged} flagged, seed={seed}")
        for kind, n in sorted(kinds.items()):
            print(f"  {n:5d}  {kind}")
    return 0 if total_findings == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--check", action="store_true",
                         help="scan both corpora with demo.anon.scan and report findings")
    parser.add_argument("--print", choices=("flat", "pane"), default=None,
                         help="print one corpus to stdout, one line each, for inspection")
    args = parser.parse_args(argv)

    if args.print:
        lines = flat_lines(args.count, args.seed) if args.print == "flat" \
            else pane_lines(args.count, args.seed)
        for line in lines:
            print(line)
        return 0

    if args.check:
        return check(args.seed, args.count)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
