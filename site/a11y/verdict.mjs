// Judgment and exit code for the accessibility gate's self-test (design gate 6).
// Owner: ATACE Working Group.
//
// This module has no imports on purpose. The scanner (axe_scan.mjs) needs
// playwright and a browser. This half needs only node, so the tests that prove
// the gate can fail run in every CI job, not only the one that installs the
// tooling. The scanner hands its scans in as functions, which lets a test swap
// in fake findings and drive every failing branch.

export const SCHEMES = ["light", "dark"];

// The rules the known-bad fixture in axe_scan.mjs plants on purpose. Each must
// fire in every color scheme.
export const BAD_WANT = ["color-contrast", "label", "html-has-lang"];

export function describe(f) {
  return `${f.path} [${f.scheme}] ${f.rule}: ${f.detail}`;
}

// Returns the list of problems, empty when the gate is trustworthy. Each
// wanted rule must fire in each scheme, so a scan that silently skipped the
// dark pass fails.
export function selfTestVerdict(badFailures, goodFailures) {
  const problems = [];
  for (const scheme of SCHEMES) {
    const fired = new Set(badFailures.filter((f) => f.scheme === scheme).map((f) => f.rule));
    for (const want of BAD_WANT) {
      if (!fired.has(want)) problems.push(`the gate missed ${want} on the known-bad page [${scheme}]`);
    }
  }
  for (const f of goodFailures) problems.push(`the gate fired on the known-clean page: ${describe(f)}`);
  return problems;
}

// Runs both scans, sets process.exitCode, and returns the same code: 0 when
// the gate proved itself, 1 when it did not. Setting the exit code here, not
// in the caller, leaves the scanner no hand-off line that could drop it. The
// raw findings go to `report` before any judgment, so a caller can check them
// without trusting the verdict.
export async function runSelfTest(scanBad, scanGood, { report, log = console.log, error = console.error } = {}) {
  const bad = await scanBad();
  const good = await scanGood();
  if (report) await report({ bad, good });
  const problems = selfTestVerdict(bad, good);
  if (problems.length) {
    for (const p of problems) error(`a11y self-test: ${p}`);
    process.exitCode = 1;
    return 1;
  }
  log(`a11y self-test: the gate fired ${bad.length} times on the known-bad page ` +
    "and stayed quiet on the known-clean page");
  process.exitCode = 0;
  return 0;
}
