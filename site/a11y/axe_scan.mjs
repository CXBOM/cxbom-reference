// Accessibility gate for cxbom.org (design gate 6). Owner: ATACE Working Group.
//
// Usage, from site/:
//   node a11y/axe_scan.mjs dist          scan every page of a build
//   node a11y/axe_scan.mjs --self-test [--report FILE]
//                                         prove the gate fires on a known-bad page
//                                         and stays quiet on a known-clean one,
//                                         optionally writing the raw findings
//                                         of both scans to FILE as JSON
//
// Serves the build from 127.0.0.1 only, opens every HTML page in Chromium in the
// light and dark color schemes, and runs axe-core with the WCAG 2.0, 2.1 and 2.2
// A and AA rule tags. It also checks reflow: at 320 CSS px the page must not
// scroll sideways. Any violation exits 1. axe-core runs here in CI and is never
// copied into the site. The self-test's judgment and exit code live in
// verdict.mjs, which needs no browser, so tests can drive them with only node.
import { createServer } from "node:http";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import { extname, join, relative, resolve, sep } from "node:path";
import { chromium } from "playwright";
import AxeBuilder from "@axe-core/playwright";
import { SCHEMES, describe, runSelfTest } from "./verdict.mjs";

const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const TYPES = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".json": "application/json",
  ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8" };

// Three genuine, axe-detectable violations: a real contrast failure (not a
// color the rule merely dislikes in isolation), a form control with no
// accessible name, and a document with no language declared. None of these
// is a synthetic marker a scanner could special-case; each is the ordinary
// failure a real page ships when nobody checks. verdict.mjs names the rules
// these three must trip (BAD_WANT).
const BAD_PAGE = `<!doctype html><html><head><title>bad</title></head><body>
<input type="text">
<p style="color:#bbb;background:#fff">low contrast text</p>
</body></html>`;

// The clean counterpart: same shape, each defect fixed. A scanner that
// always fails would still catch BAD_PAGE, so this half of the self-test is
// what actually proves the gate is judging content, not just failing.
const GOOD_PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>good</title></head><body>
<label for="name">Name</label><input id="name" type="text">
<p style="color:#111;background:#fff">high contrast text</p>
</body></html>`;

function serve(root, override) {
  const base = resolve(root);
  const server = createServer(async (req, res) => {
    const path = decodeURIComponent(new URL(req.url, "http://127.0.0.1").pathname);
    if (override) { res.writeHead(200, { "content-type": TYPES[".html"] }); res.end(override); return; }
    const file = resolve(base, "." + (path.endsWith("/") ? path + "index.html" : path));
    if (file !== base && !file.startsWith(base + sep)) { res.writeHead(403); res.end(); return; }
    try {
      const body = await readFile(file);
      res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404); res.end();
    }
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server)));
}

async function pages(root) {
  const out = [];
  for (const entry of await readdir(root, { recursive: true, withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith(".html")) {
      const rel = relative(root, join(entry.parentPath ?? entry.path, entry.name)).split(sep).join("/");
      out.push("/" + rel.replace(/(^|\/)index\.html$/, "$1"));
    }
  }
  return out.sort();
}

async function scan(origin, paths) {
  const browser = await chromium.launch();
  const failures = [];
  try {
    for (const scheme of SCHEMES) {
      const context = await browser.newContext({ colorScheme: scheme, reducedMotion: "reduce" });
      for (const path of paths) {
        const page = await context.newPage();
        await page.goto(origin + path, { waitUntil: "load" });
        const result = await new AxeBuilder({ page }).withTags(TAGS).analyze();
        for (const v of result.violations) {
          failures.push({ path, scheme, rule: v.id, detail: `${v.help} (${v.nodes.length} nodes)` });
        }
        await page.setViewportSize({ width: 320, height: 800 });
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        if (overflow > 0) failures.push({ path, scheme, rule: "reflow", detail: `scrolls ${overflow}px sideways at 320px` });
        await page.close();
      }
      await context.close();
    }
  } finally {
    await browser.close();
  }
  return failures;
}

async function scanFixture(page) {
  const server = await serve(".", page);
  const origin = `http://127.0.0.1:${server.address().port}`;
  const failures = await scan(origin, ["/"]);
  server.close();
  return failures;
}

async function selfTest(reportPath) {
  const report = reportPath ? (findings) => writeFile(reportPath, JSON.stringify(findings)) : undefined;
  // runSelfTest sets the exit code itself. The process then ends on its own
  // once the browser and servers are closed.
  await runSelfTest(() => scanFixture(BAD_PAGE), () => scanFixture(GOOD_PAGE), { report });
}

async function main() {
  const arg = process.argv[2];
  if (arg === "--self-test") {
    const rest = process.argv.slice(3);
    if (rest.length && !(rest.length === 2 && rest[0] === "--report")) {
      console.error("usage: node a11y/axe_scan.mjs --self-test [--report FILE]");
      process.exit(2);
    }
    await selfTest(rest[1]);
    return;
  }
  if (!arg) { console.error("usage: node a11y/axe_scan.mjs <dist> | --self-test"); process.exit(2); }
  // A missing build directory is a setup error, not zero pages to check. Name
  // it plainly instead of letting readdir's ENOENT surface as a raw stack
  // trace, and instead of the scan silently reporting nothing to check.
  let dirStat;
  try {
    dirStat = await stat(arg);
  } catch {
    console.error(`a11y: build directory ${JSON.stringify(arg)} not found; run the site build first`);
    process.exit(2);
  }
  if (!dirStat.isDirectory()) {
    console.error(`a11y: ${JSON.stringify(arg)} is not a directory`);
    process.exit(2);
  }
  const paths = await pages(arg);
  if (paths.length === 0) { console.error(`a11y: no pages under ${arg}`); process.exit(2); }
  const server = await serve(arg);
  const origin = `http://127.0.0.1:${server.address().port}`;
  const failures = await scan(origin, paths);
  server.close();
  for (const f of failures) console.error(`a11y: ${describe(f)}`);
  if (failures.length) process.exit(1);
  console.log(`a11y: ${paths.length} pages pass in ${SCHEMES.length} color schemes`);
}

await main();
