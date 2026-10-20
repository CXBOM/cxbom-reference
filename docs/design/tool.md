# cxbom tool: proxy, attestation, emitter, CLI

Version 4.0 (2026-09-24). Owner: ATACE Working Group.

Status: **design frozen for implementation of the Oct 3 slice.** History:

- v1.0: approved in brainstorming.
- v2.0: applied the Round A premortem (37 findings).
- v3.0: applied Round B (16 merged findings) and four owner decisions:
  - full scope for October 27
  - lock entries signed with a user-level key
  - a correction slide for the abstract's CVE claim
  - owner actions on the parking page and the PyPI name
- v4.0: applied Round C (31 merged findings).

The premortem ledger lives outside this repo. A Round D premortem runs against
the Oct 3 code.

## 1. Purpose

Practitioners install this tool after the October 27 talk. It does two jobs,
each at the point where it can observe the truth:

1. **`cxbom proxy`** checks that what an MCP server tells the model is what a
   human reviewed and signed: tool definitions, server instructions, and prompt,
   resource, and template listings. It also checks that the server was launched
   with the signed argv, launcher binary, pinned files, and environment. Anything
   changed or unsigned is blocked before the model reads it.
2. **The `cxbom` emitter library** writes a complete, honest CxBOM 0.3.0 record
   where an application assembles its context. Each record is bound to the live
   proxy session that verified each tool.

The proxy never writes a CxBOM record, because it sees only the MCP slice of the context.

## 2. Scope and threat model

**Actors defended against:**

- **(a)** A server that changes what it tells the model after approval.
- **(b)** An attacker who can write workspace files. That includes the MCP
  config and its `env` block, `cxbom.lock`, and files an injected agent writes.
  This is the primitive behind CVE-2025-54135 and CVE-2025-54136.

Defenses for (b) rest on four things:
- a signing key and trust manifest that live under the user's real home
  directory, resolved from the OS user database and never from environment
  variables;
- a passphrase read only from the controlling terminal;
- a state directory outside the workspace;
- the proxy computing the child's environment itself.

**Out of scope, stated on the site and in the talk:**

- **A hostile server process.** A stdio server is code running as the user. It
  can read and exfiltrate files without touching the model.
- **An attacker who controls the user's real home directory, reads and cracks
  the encrypted key, or types the passphrase.** This includes an agent running
  arbitrary shell commands as the user while the user supplies the passphrase.
- **Authenticating attestation logs against another process running as the same
  user.** Logs are integrity-checked and kept in a 0700 directory outside the
  workspace. They are not authenticated.

**Not covered in this version.** Listed in `cxbom --help`, on the site, and on a talk slide:

| Channel | Instead |
|---|---|
| Tool results, resource bodies, prompt bodies | Recorded by the emitter as unverified components |
| Transitive dependencies of registry-runner packages, and code imported by a local server outside `--pin-tree` | The runner binary, its interpreter, the exact top-level package version or image digest, pinned files, and the registry environment are enforced |
| Registry runners `approve` does not recognize (any tool not in the section 6 runner table) | Their argv is still pinned. Prefer a listed runner or a pinned local tree |
| A runner started through a wrapper that `approve` does not recognize | `env`, `nice`, `timeout`, `nohup`, `stdbuf`, and the common shells are recognized. A launch through one is refused when a shell carries `-c`, `env` carries `-S`, or a later word names a runner, an interpreter, or another wrapper. A shell handed a script file, and a wrapper handed a program cxbom does not recognize, are not inspected. Start the runner directly |
| A container runner pointed at another daemon (`-H`, `--context`) | The image digest is pinned. Where it runs is not |
| A copy or hard link of a runner script under an unrecognized name | Runner identity is by name. Keep runners on the trusted search path |
| `.pth` files, `sitecustomize`, and imports resolved from a system interpreter's own site-packages | Everything the interpreter loads from its own prefix carries the same trust as the trusted search path. For code you control, run from a pinned venv made with `python -m venv --copies` |
| `npx`: the pin covers the npm shim script and `node`, not npm's library | Prefer `uvx` or a pinned local tree |
| Streamable HTTP servers | stdio only |
| A pinned file or tree swapped between the launch check and the exec by a process racing the proxy | Pins are checked immediately before spawn. Keep the workspace free of untrusted writers while the proxy starts |
| Revoked-key backdating: a stolen, revoked key signs entries with an `issuedAt` before its revocation | `entrySeq` and the high-water mark bound rollback. Observe and sampling entries have no tool-set expiry, so this risk is accepted for them by owner decision 2026-10-05. A `notAfter` the owner sets still ends an entry |
| prompts, resources, resource templates | slice 1 verifies tools only and refuses the rest |
| Hostnames under a TLD outside `approve`'s fixed list | The identifying-content check flags hostnames under a fixed TLD list only (section 7 step 1). Review argv and pinned values before approving |

**CVE coverage.** Every talk claim must match this table.

| CVE | Mechanism | CxBOM's role |
|---|---|---|
| CVE-2025-54136 (MCPoison, fixed in Cursor 1.3 by re-prompting) | A trusted MCP config is edited to run a different command | The signed lock refuses a changed command, binary, or environment while the `cxbom proxy` wrapper is still in place. If the edit removes the wrapper, nothing in slice 1 detects it. `cxbom scan` and `cxbom guard` (next plan, section 11) will detect it when they run, and will not prevent it |
| CVE-2025-54135 (CurXecute, fixed in Cursor 1.3.9 by re-prompting) | Prompt injection writes an MCP config that runs an attacker command without approval | Not prevented, and not detected in slice 1. `scan` and `guard` (next plan) will detect the new, unwrapped server once built. An injected agent cannot produce a valid signature |
| EchoLeak (CVE-2025-32711) | Attacker text in retrieved content steers the model | Not a tool-definition inversion and not gated. The emitter records the retrieved content as an unverified ring-1 component |
| Tool-definition rug-pull (no single CVE) | An approved tool's description changes | Definition pin in the signed lock (enforced) |

## 3. Hard constraints

- **CxBOM schema 0.3.0 is current.** 0.2.0 stays in the tree, byte-identical, for
  the ATACE paper and the recorded takes.
  - The emitter writes 0.3.0 records only.
  - Every 0.3.0 record must pass the 0.3.0 validator. 0.2.0 records still pass
    the 0.2.0 validator, vendored byte-identical from `CXBOM/ATACE` commit
    `3e7f88f` with only its two data-path constants moved to `importlib.resources`.
  - Tool-side meaning checks live in `consistency.py`.
  - Anything 0.3.0 cannot express goes into contracts or into `schema.fieldGlossary`.
- **The trust-inversion detector is ATACE's, byte-identical.** The schema defines
  positional authority as assembly position, not a model weight. A registered trust-downgrade boundary removes the structural
  inversion (section 9.5), and the record says it changes assembly, not model weighting.
  Integrity is reported only through `serverChecksumVerified` and never changes
  `mitigationStatus`.
- **Anonymity.** None of the following may carry hostnames, usernames, home
  paths, personal names, or IP addresses. `approve` checks pin values before it
  hashes them. Any child stderr the proxy re-emits has absolute paths rewritten
  relative to the lock directory. The demo uses a demo-only signing key.
  - records, attestations, locks, event logs
  - proxy stderr and `notifications/message` text
  - wheel, sdist, and archive headers
  - anything published
- **MCP protocol.**
  - stdio, dual-era. Modern is `2026-07-28`, legacy is `2025-11-25` and earlier.
  - No JSON-RPC batching.
  - Every intercepted line is exactly one JSON-RPC shape. A bare `\r` (other
    than one trailing a CRLF line), a raw U+2028, U+2029, or U+0085, and an
    `id` longer than 1 KiB each make a line fail the shape check.
  - Slice 1 verifies tools only. `prompts/*` and `resources/*` requests are
    refused, and those capabilities are removed from the `initialize` result
    (section 8.4).
- **Python 3.10 or newer.**
  - Core install: `rfc8785>=0.1.4,<0.2`, `jsonschema[format-nongpl]>=4.23,<5`,
    `rfc3339-validator`, `cryptography>=42,<51`.
  - Extra `cxbom[emit]`: `tokenizers>=0.20,<0.24`.
- **No MCP SDK.** Messages the proxy does not rewrite are forwarded byte-for-byte.

## 4. Components

```
cxbom/
  paths.py          user config and state dirs from pwd.getpwuid(os.getuid()).pw_dir only
  jsonstrict.py     strict parser keeping raw byte spans and number lexemes
  canonical.py      RFC 8785 hashing: tools, instructions, launch, trees
  signing.py        Ed25519 envelopes, key files, trust manifest, high-water marks, revocation
  lockfile.py       cxbom.lock read, write, verify (C3)
  store.py          content-addressed store: wire definitions, rendered texts, instructions
  state.py          enforcement state function shared by proxy and emitter
  attestation.py    write-ahead attestation log (C3)
  mcpclient.py      minimal dual-era stdio client for approve and check-drift
  display.py        escaped rendering of untrusted text for human review
  relay.py          byte-level relay: framing, id correlation, single writer per stream
  proxy.py          interception, era latch, re-listing, capability stripping, splicing
  launch.py         child environment, binary and interpreter hashing, watchdog
  approve.py        review, per-era pinning, signing
  renderers.py      closed renderer registry and trust-boundary registry
  templates.py      per-family marker tables (strings and ids), pinned by chat_template hash
  assembly.py       Assembly: the emitter's public API (ids mode and text mode)
  emitter.py        Assembly -> 0.3.0 record
  findings.py       exact finding templates
  consistency.py    tool-side record meaning checks
  detectors.py      vendored from ATACE 3e7f88f, byte-identical
  validator.py      vendored, two declared hunks (see below)
  crosswalk.py      vendored, one declared hunk: data path via importlib.resources
  _data/            schema and catalogs incl. SOURCES.json, byte-identical
  scan.py, guard.py, gate.py, cli.py
```

Every vendored file's SHA-256 is listed in `spec/published.lock.json` under
`vendored`, and a test enforces it.

A vendored file that differs from ATACE 3e7f88f carries a declared patch set in
its lock entry: a list of hunks, each holding the upstream text (`from`), the
text that replaces it (`to`), and the reason for the edit. Two files are
patched.

- `crosswalk.py`, one hunk. It moves the catalog path from the ATACE repo
  layout to `importlib.resources`, so the catalogs load from the installed
  wheel.
- `validator.py`, two hunks.
  1. The module up to the end of `check_all`. It moves the schema path to
     `importlib.resources` for the same reason. The nullsum fix rounds 1 to 3
     and ruling 2 fix round 1 widened it so a malformed record is reported and
     never raised on. Every record read goes through one typed accessor layer,
     the walks are iterative and bounded, and a value is rendered by an
     iterative, size-bounded renderer that matches exact builtin types and
     gives every other type a fixed placeholder, so it runs no code the value
     supplies and cannot raise. `check_all` refuses a constructed document
     holding a type `json.loads` cannot produce before any check runs.
  2. `main()`. Owner ruling 2 (2026-09-27) reversed the earlier instruction to
     leave it upstream-identical. It refuses a file it cannot read, that is not
     a regular file, or that it cannot decode or parse, with one stderr line and
     exit status 1 instead of a traceback. That includes nesting deeper than
     `json.loads` follows and an integer wider than the interpreter converts.
     Every line names the file by its position on the command line, never by
     its path. Every character that is not printable is written as a visible
     escape, so one emitted line is one physical line and writing cannot raise.

The reversal is the provenance proof. `tests/test_vendored_atace.py` requires
every hunk to state a reason and every `to` to occur exactly once in the
shipped file. It then restores each hunk's `from` in place and checks that the
result hashes to the entry's `upstreamSha256`, which is the SHA-256 of the
file at ATACE 3e7f88f. An edit outside a declared hunk, an undeclared hunk,
or a hunk without a reason fails that test. For `validator.py`, only 60 of the
17,172 upstream bytes lie outside the two hunks. Provenance rests on the
declaration and the reversal, not on how much of the file is left untouched.

## 5. Parsing and hashing

**Strict parsing** (`jsonstrict.py`) applies to every intercepted line:

- strict UTF-8
- duplicate keys rejected
- lone surrogates rejected
- non-finite numbers and overflow such as `1e400` rejected
- raw byte spans kept for every value and the original lexeme for every number
- lines over 64 MiB fail

**Hashes** (`canonical.py`):

- **`tool_sha256`**: RFC 8785 over the whole wire tool object, minus approved
  `ignoreFields`.
  - An `ignoreFields` entry must be an exact leaf pointer under `/_meta`.
  - `approve` shows the diff and stores a reason for each entry.
  - At every verdict, the value at an ignored pointer must be a number, a
    boolean, null, or an RFC 3339 string of 40 bytes or fewer. Anything else
    makes the verdict `changed`.
- **`instructions_sha256`**: RFC 8785 over the JSON string.
- **`launch_sha256`**: RFC 8785 over `{argv, binary, interpreter, files, trees, env}`.
- **`tree_sha256(dir)`**: RFC 8785 over sorted `[relative path, file sha256]`
  pairs. Symlinks are refused.
- **Uncanonicalizable items** get verdict `uncanonicalizable`. They are blocked
  and cannot be approved.
- **The store** lives in `<state-dir>/store/`, mode 0700, with files at 0600.
  - Wire definitions are keyed by full-object hash.
  - Rendered texts are keyed by `content.sha256`.
  - The pin hash is kept separately. It equals the wire-definition key whenever
    the era strips nothing, which is how a reader recovers an approved body
    from a pin alone. `approve` is the only writer and it always computes a
    pin with an empty ignore list, so a non-empty `ignoreFields` cannot reach a
    lock through it. A non-empty list can reach a lock only through an
    externally signed one, which contract C3 2.0.0 permits. Even there the pin
    diverges from the store key only when the approved object actually carried
    a value at the ignored pointer: when it never did, stripping is a no-op,
    the pin still equals the store key, and the lookup still hits.
  - Readers recompute hashes before use.
  - Changed definitions are stored unredacted and are never included in bundles.
  - **Durability.** The store is the only place an approved definition outlives
    the process that approved it. The state directory must therefore survive a
    proxy restart. A deployment that discards it, or that never receives it,
    keeps every verdict intact but loses the proxy's ability to say what a
    definition changed from when the change landed between sessions
    (section 8.7).

## 6. Lockfile, signing, and trust (contract C3 2.0.0)

```json
{
  "contract": {"name": "cxbom-lock", "version": "2.0.0"},
  "canonicalization": "RFC 8785 JSON Canonicalization Scheme",
  "lockScope": "<random 128-bit id written by cxbom init>",
  "servers": {
    "fetch": {
      "envelope": {
        "serverId": "fetch",
        "lockScope": "<same>",
        "entrySeq": 3,
        "issuedAt": "2026-10-10T18:00:00Z",
        "notAfter": null,
        "entry": {
          "argv": ["uvx", "--with", "mcp==1.30.0", "mcp-server-fetch==2025.4.7"],
          "binary": {"name": "uvx", "sha256": "<hex of realpath target>"},
          "interpreter": null,
          "files": {},
          "trees": {},
          "env": {"UV_INDEX_URL": {"sha256": "<hex>"}, "API_TOKEN": "secret"},
          "firstParty": false,
          "allowObserve": false,
          "allowSampling": false,
          "allowAcceptFlag": false,
          "renderer": "jcs",
          "clientCapabilitiesSha256": "<hex>",
          "eras": {
            "legacy": {
              "negotiatedVersion": "2025-11-25",
              "instructionsSha256": "<hex>",
              "serverInfo": {"name": "mcp-fetch", "version": "1.x"},
              "tools": {"fetch": {"sha256": "<hex>", "approvedAt": "...", "approvedBy": "demo-operator",
                                  "approvalMode": "interactive", "reason": "reviewed"}},
              "prompts": {}, "resources": {}, "resourceTemplates": {},
              "ignoreFields": []
            }
          }
        }
      },
      "signature": {"alg": "ed25519", "sig": "<base64 over RFC 8785 of envelope>"}
    }
  }
}
```

**Paths.** Every user-level path resolves from `pwd.getpwuid(os.getuid()).pw_dir`,
never from `HOME` or `XDG_*`:

- config: `<pw_dir>/.config/cxbom/`
- state: `<pw_dir>/.local/state/cxbom/`

The proxy, `approve`, and `gate` exit 2 if their own `HOME` differs from `pw_dir`.
Directories and files must be owned by the user and not writable by group or
others. Otherwise they are refused.

**Keys.**

- `cxbom keygen` creates an Ed25519 key.
  - The private key is encrypted with a passphrase.
  - The passphrase is read only from `/dev/tty`, and there is no other input path.
  - It prints the public-key fingerprint.
- `trusted.json` is a trust manifest signed by the user's key. It lists trusted
  fingerprints and any organization keys.
  - `cxbom trust add KEY.pub` and `cxbom trust revoke FINGERPRINT --after DATE`
    both require the passphrase and re-sign the manifest.
  - `.pub` files not listed in the manifest are ignored.
  - Organization keys are pinned through `trust add`, never from a repository.

**Envelopes.**

- The signature covers the whole envelope, including `serverId`, `lockScope`,
  and `entrySeq`.
- `keyId` is derived from the key that verifies, never read from the file.
- `<state>/highwater.json` records the highest accepted `entrySeq` for each
  `(lockScope, serverId)`. A lower value is refused, which blocks rollback.
- No entry has a tool-set lifetime, `allowObserve` and `allowSampling`
  included (owner decision 2026-10-05). `notAfter` is null unless the owner
  sets it, and an owner-set `notAfter` has no maximum. Once it passes, the
  entry is refused as expired. The 24-hour cap this replaces was the
  mitigation for revoked-key backdating, which section 2 now lists as an
  accepted risk.
- The proxy, the emitter, and `gate` load public keys only and never open the
  private key.

**Launch pins.**

- `argv[0]` resolves only against the trusted search path: `/usr/local/bin`,
  `/usr/bin`, `/bin`, `/opt/homebrew/bin` on macOS, and `<pw_dir>/.local/bin`.
  The caller's `PATH` is never searched, because actor (b) writes it. An
  `argv[0]` that names a path is accepted only inside a tree pinned with
  `--pin-tree`. Any other path is refused with "put the binary on the standard
  PATH or pin its tree". The pins hash bytes, and the directory a launcher runs
  from decides which siblings it runs (`uvx` runs the `uv` beside it, a Python
  binary reads the `pyvenv.cfg` beside it), so that directory must be one
  actor (b) cannot write.
- `binary` is the realpath target of `argv[0]`. The basename and hash are
  stored, never the path.
  - When that target starts with `#!`, the resolved interpreter is pinned as
    `interpreter`. The interpreter's own directory must pass the same test as
    `argv[0]`: it lies on the trusted search path or inside a tree pinned with
    `--pin-tree`. Otherwise the launch is refused with "put the interpreter on
    the standard PATH or pin its tree", because a Python interpreter reads the
    `pyvenv.cfg` beside it. The test applies to the directory as named, before
    any symlink is resolved, and again to its realpath. Both must pass, for
    the interpreter and for a path-form `argv[0]`. So a venv made with
    symlinks (the `python -m venv` default) is refused, because its
    interpreter's realpath lies outside the pinned tree. Only a venv made
    with `python -m venv --copies` passes.
  - A `#!/usr/bin/env` line may use only the `-S` option. Any other `env`
    option is refused, because options such as `-u`, `-C`, and `-P` take values
    that would hide the real interpreter, and `-i` clears `PATH` so a different
    interpreter runs than the one pinned.
  - Known shim managers (pyenv, asdf, mise, volta, nodenv, rbenv) are refused
    with the message "pass the real binary".
- `files` and `trees` store paths relative to the lock directory. At launch they
  are resolved against the lock directory and checked. An argv element that
  names a file under the lock directory, relative or absolute, is pinned. The
  value of a `--flag=value` element is treated the same way, as is the value
  of any element of the form `-Xvalue` or `name=value`, and each segment of a
  value that is a `file://` URL, starts with `@`, or is a comma or colon list.
  A candidate that exists is inside the lock directory when one of its parent
  directories has the lock directory's device and inode, so every alias the
  kernel resolves (`/tmp` for `/private/tmp`, case variants, the
  `/System/Volumes/Data` firmlink, `/.vol/<dev>/<ino>`, Unicode normalization
  variants) is caught. A candidate that does not exist uses the realpath and
  case-insensitive test. One that names a symlink there is refused. An element or `--flag=value` value that is
  path-shaped (it starts with `/`, `./`, `../`, or `~`, or contains `/` and
  its first segment exists in the lock directory, so `@scope/pkg@1.2.3` and
  `mcp/fetch@sha256:...` are not paths) and
  resolves under the lock directory but does not exist is refused with "file
  does not exist: create it before approve", because a file created after
  approval would run unpinned. A pinned file can still be swapped
  between the check and the exec by a racing process, a residual risk listed
  in section 2. `approve --pin-tree DIR`
  pins a local server's source tree. A tree that contains the lock file
  (`--pin-tree .` or any ancestor of it) is refused with "the lock file is
  inside this tree and changes when it is signed. Pin a subdirectory".
- Registry runners must pin every package they fetch. The launch pins cover
  the runner, not the package, so an unpinned launch runs whatever the registry
  serves next. `approve` identifies the runner from the casefolded basename of
  `argv[0]` and of its realpath target (`npx-cli.js` counts as `npx`,
  `npm-cli.js` and an `index.js` inside an `npm` package directory as `npm`,
  `corepack.js` as `corepack`). An interpreter counts as the runner it starts:
  `python -m pipx`, `python -m uv`, `python -m uvx`, a `python` script that is
  `pipx.pyz`, and `node` with any of the scripts above. Beyond these names, a
  `node` or `python` script whose realpath (after node's extension and
  `index` resolution, and including `__pycache__` bytecode) lies inside the
  installed package directory of `npm`, `corepack`, `pipx`, `uv`, or `uvx` is
  refused with "run the runner by its standard name", because the installed
  runner's files under another spelling are the same runner.
  A `node` or `python` launch follows an allowlist grammar, because an
  interpreter can load a runner through far more routes than a list of names
  can cover. Before the script or `-m` module, only these interpreter options
  are accepted: for `python`, `-u`, `-B`, `-I`, `-E`, `-s`, `-S`, `-O`, `-OO`,
  `-q`, `-P`, alone or combined. For `node`, `--no-warnings`,
  `--enable-source-maps`, `--no-deprecation`, `--max-old-space-size=N`, and
  `--stack-size=N`. Any other option is refused, which covers preloads
  (`-r`, `--require`, `--import`, `--loader` in any form), inline code (`-c`,
  `-e`, `-p`, `--eval`), warning and `-X` hooks, and `--env-file`. The message
  is "put the code in a pinned file". The script must be pinned: it lies in the
  lock directory or in a tree pinned with `--pin-tree` (by the device and
  inode test), or it is a runner's standard entry and goes through the runner
  grammar. A script anywhere else, the standard library included, is refused
  with the same message, because unpinned code can start any module. `-m`
  accepts a runner module (`pipx`, `uv`, `uvx`), which goes through the runner
  grammar, or a module found in the site-packages of an interpreter
  that itself lies in a pinned tree (a pinned venv), because the child searches
  only the interpreter's own paths, never the tree. The module name must not be
  a standard-library, builtin, or frozen module name in any supported Python
  version (3.9 through 3.15, removed modules included), because the stdlib
  loads ahead of site-packages.
  Any other module is refused with "put the code in a pinned file", which
  covers the standard-library launchers (`runpy`, `cProfile`, `profiling`,
  `trace`, `pdb`, `timeit`, `code`, `asyncio`), `pip`, `venv`, and modules
  from an unpinned environment. Install a server as a pinned runner package or
  pin its tree instead. A
  pinned `PYTHON*` or `NODE_*` variable is refused unless its value is empty
  or it is one of `PYTHONUNBUFFERED`, `PYTHONIOENCODING`, `PYTHONUTF8`,
  `NODE_ENV`, and `NODE_NO_WARNINGS`,
  because the rest (`NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONHOME`,
  `PYTHONSTARTUP`, `PYTHONWARNINGS`, `PYTHONINSPECT`, and others) reach the
  same load hooks from the environment. A pinned `LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`,
  `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `CLASSPATH`,
  `PERL5OPT`, `PERL5LIB`, `PERLLIB`, `PERL5DB`, `RUBYOPT`, `RUBYLIB`,
  `OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_ENGINES`, `GCONV_PATH`, or
  `LUA_INIT*` variable is refused unless its value is empty, because each loads
  code into the child. None of these, and no `PYTHON*` or `NODE_*` variable,
  may be a `secret` name, because a secret's value comes from an untrusted
  source at launch. The proxy re-applies the runner, interpreter, and
  environment rules to the signed entry at every launch, so an entry signed
  under older rules is refused if it breaks a current one. A path-form `argv[0]` gets the same runner
  package directory test as a script argument.
  An exec wrapper does not hide a runner. When `argv[0]`, by its casefolded
  basename or its realpath basename, is `env`, `nice`, `timeout`, `nohup`,
  `stdbuf`, `sh`, `bash`, `zsh`, `dash`, or `ksh`, the launch is refused if
  any later word (each element split at whitespace, quotes, and shell
  punctuation) names a registry runner, a runner's standard entry, a `python`
  or `node` interpreter, or another of these wrappers, because the runner and
  interpreter grammars read only `argv[0]`. A shell given `-c` in any option
  cluster, and `env` given `-S` or `--split-string`, is refused outright with
  "put the code in a pinned file", because a command string cannot be parsed
  safely. A wrapper this list does not name is listed in section 2.
  `corepack <pm>@X.Y.Z ...` counts as `<pm> ...`, and the package manager
  itself must carry an exact version, because corepack resolves a tag, a range,
  or a bare name against the registry. Each runner has a flag allowlist. A flag outside it,
  before the package, is refused. Nothing after the package is inspected,
  except for `npm exec` and `npm x`: npm parses flags anywhere until `--`, so
  any token after the package that begins with `-` is refused unless a `--`
  came before the package. (`npx` inserts that `--` itself.)

  | Runner | Exact pin form | Allowed flags before the package |
  |---|---|---|
  | `uvx`, `uv tool run`, `uv tool uvx` | `pkg==1.2.3`, or `--from pkg==1.2.3` | `--from`, `--with` (each pinned), `--python` |
  | `uv run` | every `--with` is `pkg==1.2.3` | `--with`, `--python`, `--no-project`, `--script` |
  | `pipx run` | `--spec pkg==1.2.3`, or `pkg==1.2.3` | `--spec` |
  | `npx`, `npm exec`, `npm x` | `pkg@1.2.3`, and every `-p`/`--package` the same | `-y`, `--yes`, `-p`, `--package` |
  | `bunx`, `bun x` | `pkg@1.2.3` | none |
  | `pnpm dlx`, `pnpx`, `yarn dlx` | `pkg@1.2.3`, and every `--package` the same | `--package` |
  | `corepack <pm>@1.2.3 ...` | the package manager's own `@X.Y.Z`, then `<pm> ...` is checked against that manager's row | none |
  | `docker run`, `docker container run`, `podman run`, `podman container run` | `image@sha256:<64 hex>`, with or without a name or tag before the `@` | every documented `run` flag (see below), plus docker's global flags before the subcommand |

  - A PyPI pin is `name==version`, where `name` is a PEP 508 project name with
    optional extras and `version` is a PEP 440 release with no wildcard, range,
    or `===`. An npm pin is `name@X.Y.Z` with optional prerelease and build
    parts, where `name` is an npm package name with an optional `@scope/`.
  - A URL, git, `file:`, or path specifier is refused, even with a
    version-shaped suffix, because it names a mutable remote or local artifact.
  - A flag between the runner and its subcommand (`npm --yes exec`,
    `uv -q tool run`) is refused.
  - `npm init <x>` and `npm create <x>` have no pin form and are refused. So
    are npm's install family (`install`, `i`, `add`, `ci`, `update`, `up`,
    `upgrade`, `dedupe`, `ddp`, and their aliases and abbreviations), because
    each fetches from the registry and runs lifecycle scripts. `docker mcp` is
    refused, because the MCP gateway fetches from a catalog. `docker compose`,
    `podman compose`, `podman kube play`, and `podman play kube` are refused,
    because they launch images named inside a file, where no digest pin covers
    them. Run the image directly with a digest.
  - A `uv run` target that is a pinned file with a PEP 723 inline metadata
    block is read at approve. Every dependency in it must be an exact PyPI pin,
    and a `requires-python` line is allowed. Any other dependency form is
    refused, because uv fetches it from the registry at every launch.
  - Container runners parse every documented `run` flag with its arity, so the
    image is the first argument that is not a flag or a flag's value. The
    flag tables are generated from `docker run --help` and `docker --help`
    (Docker 29.5.2) and from the podman v5.6.1 `podman-run` option docs, and
    are vendored with their source. Short flags combine (`-it`) and take
    attached values (`-eKEY=v`). Boolean flags take only the `=true` or
    `=false` form. A flag missing from the table is refused, naming the flag,
    because the image position cannot be found past it. Podman's `--rootfs`
    is refused, because it replaces the image with a host path. The digest
    pins the image the flags run, so no flag is refused for what it does.
    Podman global flags before `run` are refused. An image reference that
    starts with a transport-style prefix (a scheme word followed by `:` that is
    not a registry `host:port/`) is refused, because it names a local path or
    store, not a registry digest. A bind-mount source in any form (`-v`,
    `--volume`, clustered `-iv...`, `-v=`, and the `source=` or `src=` field
    of `--mount`) is a path candidate like any other. A daemon reached with `-H`/`--host` or `--context` runs the
    same digest-pinned image on another host, which the pin does not govern
    (listed in section 2).
  - The message is "pin an exact package version", followed by the offending
    argument, escaped. There is no override flag.
- `cxbom approve --rebind-binary SERVER` is a feature of the next proxy
  plan. It will re-probe and re-sign only if every definition hash is
  unchanged, and record `approvalMode: "rebind"`. Until it lands, the proxy's
  exit-2 message for a changed binary or interpreter names the binary and says
  to re-run `cxbom approve` for the server.

**Child environment.** The proxy builds it. It never inherits it.

- `HOME` is `pw_dir`.
- `TMPDIR` is a fresh 0700 directory under the platform temp root.
- `PATH` is the trusted search path above, preceded by the pinned tree's
  directory when `argv[0]` comes from one.
- `LANG`, `LC_ALL`, `TERM`, `USER`, and `LOGNAME` pass through.
- `PYTHONNOUSERSITE=1` is always set as defense in depth: the user site
  loads ahead of a pinned module and is not pinned.
- `PYTHONDONTWRITEBYTECODE=1` is always set, because a Python server that
  imports a sibling module would otherwise write `__pycache__` into its
  pinned tree on the first launch, `approve`'s own probe included, and every
  later launch would fail the tree pin.
- Both are fixed by the proxy and are not part of the pins. A lock cannot pin
  either one or name it `secret`.
- Pinned variables must match their hash.
- `secret` names must be present. Their values come from an untrusted source and
  are not hashed.
- Nothing else passes. Variables that redirect trust or code can only be pinned:
  `SSL_CERT_*`, `*_PROXY`, `NO_PROXY`, `REQUESTS_CA_BUNDLE`,
  `NODE_EXTRA_CA_CERTS`, `XDG_*`, `UV_*`, `PIP_*`, `npm_config_*`, `PYTHON*`,
  `NODE_*`, `LD_*`, `DYLD_*`, `DOCKER_*`, `BUN_*`, `COREPACK_*`, `BASH_ENV`,
  `ENV`, `VIRTUAL_ENV`, `CONDA_*`, `GIT_*`, `CURL_CA_BUNDLE`, `JAVA_TOOL_OPTIONS`,
  `_JAVA_OPTIONS`, `PERL5*`, `RUBY*`, `GEM_*`, `BUNDLE_*`.

**Flags.** `--mode observe` requires `allowObserve`. `--lock` and `CXBOM_LOCK`
select among signed envelopes only.

## 7. `cxbom approve`

```
cxbom approve --server-id ID --approver ROLE [--lock PATH]
              [--era legacy|modern|both] [--client-capabilities JSON]
              [--ignore POINTER --reason TEXT]... [--accept SHA256 --reason TEXT]...
              [--pin-env NAME]... [--secret-env NAME]... [--pin-tree DIR]...
              [--startup-timeout SECONDS] [--allow-nonprintable --reason TEXT]
              [--allow-observe] [--not-after TIME]
              -- <server command...>
```

1. **Validate.**
   - `ROLE` must match `^[A-Za-z0-9 _.-]{1,64}$`.
   - argv and pinned values are rejected if they contain any of:
     - a home path
     - URL userinfo
     - a hostname or IP literal
     - a known credential prefix (`sk-`, `ghp_`, `github_pat_`, `xox`, `AKIA`, `glpat-`)
     - an `Authorization` header
     - a token of 20 or more characters with entropy above 4.0 bits per character
   - The hostname check flags a name only under a fixed TLD list (`com`,
     `net`, `org`, `io`, `dev`, `ai`, `app`, `cloud`, `local`, `lan`,
     `internal`, `home`, `corp`, `edu`, `gov`, `co`, `us`, `uk`, `de`,
     `localdomain`), and exempts the public registries and the reserved
     `example.com`, `example.net`, and `example.org`. A hostname under any
     other TLD passes. This is a stated limit (section 2).
   - `--startup-timeout` takes a finite number of seconds in (0, 3600].
   - `--allow-observe` needs no `--not-after`, and the entry then has no
     expiry (owner decision 2026-10-05). `--not-after`, when given, must be an
     RFC 3339 UTC time with a `Z` suffix and in the future. It has no maximum.
   - An existing entry for the server must still verify before `approve`
     extends it. Once an owner-set `notAfter` has passed, `approve` refuses with
     "Refusing to extend it", and recovery is a fresh lock from `cxbom init`.
2. **Launch** exactly as the proxy will (section 6).
   - A `-m` module is accepted by its presence in the
     site-packages of an interpreter inside a pinned tree
     (`<prefix>/lib/python*/site-packages`). The entry records the tree hash,
     not the module, so every module already in that directory is reachable
     under the same pin, and a module the tree gains later moves the tree hash
     rather than being named. A non-runner module under a system interpreter's
     own site-packages is refused instead, because nothing pins it. This is a
     stated limit (section 2).
3. **Probe the era.**
   - `server/discover` first, then `initialize` on a non-modern error.
   - The timeout starts at the child's first output byte, or at `--startup-timeout`
     (default 60 s), whichever comes first.
   - An ambiguous probe requires `--era`.
   - `--era both` pins each supported era.
   - The declared client capabilities (`--client-capabilities`, default `{}`) are
     hashed into the entry.
4. **Read every page** of `instructions`, `tools/list`, `prompts/list`,
   `resources/list`, and `resources/templates/list`. It never calls, reads, or
   gets anything.
5. **Review.** Each new or changed item is printed through `display.py`.
   - C0 and C1 controls, bidi controls, zero-width characters, tag characters,
     and non-ASCII outside a documented allowlist are shown as `\u{XXXX}`, with a count.
   - `y` is refused when that count is above 0, unless `--allow-nonprintable`
     gives a stored reason.
6. **`--accept`** records `approvalMode: "accept-flag"`, and `approve` sets
   `allowAcceptFlag` on any entry that holds an accept-flag pin. The proxy
   honors such a pin only when the entry sets `allowAcceptFlag`.
7. **`--first-party`** (a next-plan flag, not in slice 1) needs typed confirmation. It is refused for every
   runner in the section 6 runner table (`uvx`, `uv`, `pipx`, `npx`, `npm`,
   `bunx`, `bun`, `pnpm`, `pnpx`, `yarn`, `docker`, `podman`, `corepack`).
8. **Sign.**
   - Print server id, argv, every added or changed hash with its first 200
     escaped characters, and any change to `firstParty`, `allowObserve`,
     `allowSampling`, or `allowAcceptFlag`.
   - Require typing the server id, then the passphrase from `/dev/tty`. With no
     controlling terminal, exit 2.
   - Increment `entrySeq`, sign, write the lock canonically, and update the store.
9. **Warn** that approval is the only defense against a definition that was
   malicious when it was approved.

## 8. `cxbom proxy`

```
cxbom proxy --server-id ID [--lock PATH] [--mode enforce|observe]
            [--state-dir DIR] [--events FILE] [--redact-sha256 HEX]... -- <server command...>
```

### 8.1 Startup

1. **Check the paths** (section 6). Resolve the lock, verify the envelope
   (signature, trust manifest, scope, high-water mark, `notAfter`), and validate
   against C3. Exit 2 on any failure.
2. **Check the launch.** Compare argv, binary, interpreter, files, trees, and
   pinned environment against the entry. Exit 2 on mismatch. `observe` without
   `allowObserve` also exits 2.
   - With `--events`, a refusal of the entry or of a launch item writes one
     C2 1.2.0 `launch_refused` sidecar line before the proxy exits: `item`
     names what failed (`entry`, `argv`, `binary`, `interpreter`, `files`,
     `trees`, `env`, or `policy`), `proxySessionId` is `null`, and `localSeq`
     is 0, because no session is open yet (section 8.7).
3. **Open the session.**
   - Create `proxySessionId` (UUIDv4).
   - Open `<state-dir>/attest/<serverId>-<proxySessionId>.jsonl` with
     `O_APPEND | O_CLOEXEC` and hold an exclusive `flock` on it for the proxy's
     lifetime.
   - The default state dir is the user state dir. A `--state-dir` inside a git
     worktree is refused.
   - The state dir must not be a Docker Desktop bind mount shared with the host.
4. **Spawn.**
   - Start the watchdog with fork and exec from the main thread before any other
     thread starts. The watchdog calls `setsid`, ignores `SIGINT`, `SIGTERM`, and
     `SIGHUP`, and receives only the read end of an `O_CLOEXEC` pipe.
   - Spawn the child with the section 6 environment, a fresh temporary working
     directory, and its own process group.
   - When the pipe closes, the watchdog sends `SIGTERM` to the child's group,
     waits 1 s, then sends `SIGKILL`.
   - On Linux, the child also gets `PR_SET_PDEATHSIG`.
   - Grandchildren that leave the group with `setsid` or `setpgid` are not reached.
   - A spawn failure after the launch checks pass ends the log with
     `internal-error` and exits 70.

### 8.2 Relay

- **Streams.** One reader and one writer per direction. All proxy-originated
  lines go through the same writer.
- **Pending table.** Keyed by exact JSON type and value of `id`, plus direction.
  Each entry holds:
  - the method
  - the request's `_meta` (modern)
  - `params.cursor`
  - the chain id
- **Response matching.** In enforce mode, a response is forwarded only if its id
  exactly matches a pending request from the opposite direction.
- **Cancellation.** An entry is cleared only by its response, or by a
  `notifications/cancelled` from the side that made the request. After a cancel
  the entry is kept for 30 s, and the late response is dropped. A held, unforwarded
  `tools/call` that is cancelled is dropped.
- **Proxy-originated ids.** They have the form `cxbom-<proxySessionId>-<n>`. A
  client request using the prefix `cxbom-` is rejected.
- **Proxy-originated modern requests.** They copy the `_meta` of the most recent
  client request of the same method, after capability stripping.
- **Rewriting.** Rewritten results splice original byte spans.
  - Existing keys are replaced in place.
  - Server-supplied `org.cxbom/*` keys are removed.
- **Limits.**
  - A request `id` over 1 KiB fails the shape check.
  - At most 4096 requests and 256 MiB of retained bytes are in flight at
    once, held calls and held lists included. Past either cap a new request
    gets `-32603`.
  - A proxy-owned listing chain follows at most `MAX_CHAIN_PAGES` (100)
    pages and fails on a cursor it has already seen in that chain, so a
    looping server cannot page forever.
- **Client notifications.** Enforce mode drops a client notification whose
  method does not start with `notifications/`, with a diagnostic. It has no
  gating path and no response channel.
- **Strict-parse failure** (enforce mode):
  - drop the line
  - answer pending requests to that server with `-32603`
  - move every item to `unverified`, written ahead of forwarding

  In observe mode the line is forwarded with a diagnostic.

### 8.3 Era latch

The era is a property of the server process and is latched by the server's answer:

- A `DiscoverResult`, or a recognized modern error, latches `modern`.
- A `server/discover` error that is not a recognized modern error is forwarded
  and latches nothing.
- A client `initialize` sent after a failed or unanswered probe, and before any
  list result has been forwarded, latches `legacy`.

Rules:

- Nothing else changes the latch. Concurrent eras in one process are refused in
  enforce mode.
- Legacy results are checked against the `legacy` pin set. The negotiated version
  is written in a `protocol` line.
- Modern results are checked against the pin set for their request's
  `protocolVersion`. A missing set gives `unpinned-version`.
- If the client's declared capabilities hash differs from
  `clientCapabilitiesSha256`, every item gets `unpinned-version`.

### 8.4 Interception

| Message | Action |
|---|---|
| Client `initialize` (legacy) or modern request with `clientCapabilities` | Remove `sampling` when `allowSampling` is false |
| `initialize` or `server/discover` result | Hash `instructions` against the pin. Record `serverInfo` in the `server` line. On change: enforce mode blanks `instructions` and blocks every item. Set `ttlMs` to 0 and `cacheScope` to `"private"`. Add `_meta["org.cxbom/proxySessionId"]` |
| `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list` results, every page | Verdict per item. Enforce mode splices out blocked items. Rewrite `ttlMs` and `cacheScope`. Add `_meta["org.cxbom/proxySessionId"]` |
| `tools/call` for an item not `allowed` | If the item is `not-listed` or `unverified`, the proxy runs its own full chain first. A block answers `-32602` "Unknown tool: NAME (blocked by cxbom: REASON)" |
| A held `tools/call` or held list that waits 10 s | The call is blocked with `-32602` and reason `relist-timeout`. A list held for the proxy's own discovery gets `-32603` |
| Client `prompts/*` or `resources/*` request (enforce) | `-32601` "cxbom: this version verifies tools only". The `prompts` and `resources` capabilities are removed from the `initialize` result |
| `input_required` result on `tools/call`, `prompts/get`, or `resources/read` with `sampling/createMessage`, while `allowSampling` is false | `tools/call`: replaced by an `isError` tool result. Others: `-32603` |
| Legacy server-initiated `sampling/createMessage`, while `allowSampling` is false | JSON-RPC error. Elicitation passes through |
| `notifications/tools/list_changed` (legacy, or inside `subscriptions/listen`) | Forwarded. The proxy re-lists with its own ids. Only items whose hash changed leave `allowed` |
| Proxy `notifications/message` | Only on a modern request carrying `logLevel`, or in legacy after `notifications/initialized`. Otherwise the reason goes in the `-32602` text |

### 8.5 Enforcement state (`state.py`, shared with the emitter)

State is kept per `(serverId, itemType, name)`.

| State | When | `tools/call` in enforce mode |
|---|---|---|
| `not-listed` | Session start | Proxy lists, then decides |
| `allowed` | The latest completed chain showed the item's hash equal to the signed pin for the latched era. The latest `server` line has verdict `pinned-match`. The name appeared once in that chain | Forwarded |
| `blocked` | Verdict `unpinned`, `unpinned-version`, `changed`, `uncanonicalizable`, `duplicate-name`, `not-approved`, or `accept-flag-not-allowed`, or the latest `server` line has any verdict other than `pinned-match` | Blocked |
| `unverified` | After a strict-parse failure, while a re-list for a changed item is in progress, or when a `pinned-match` verdict arrives before any `server` line | Blocked |

- **Chains.** A chain starts at a request without a cursor. It continues only
  with a `nextCursor` the proxy saw, and chains are ordered by start time.
- **Per-page commits.** Verdicts commit per page. An item is absent only after a
  full chain.
- **Precedence.** An earlier chain never overrides a later one.
- **Server line first.** The proxy writes the `server` line before any verdict
  line and before forwarding any list result. In modern era it issues its own
  `server/discover` when the client skipped discovery.

### 8.6 Attestation log (contract C3 2.0.0)

- **Location:** `<state-dir>/attest/`, mode 0700.
- **Write-ahead:** every `server`, `verdict`, and `state` line is a single
  `os.write` to the `O_APPEND` descriptor, and it happens before the proxy forwards
  the message that caused it.
- **Durability:** fsync at `end` and on `SIGTERM`.
- **Never dropped:** attestation lines never share a queue with events.
- **`seq`** is contiguous.
- **Readers** ignore a final line with no trailing newline.

| `kind` | Fields |
|---|---|
| `session` | `contract`, `proxySessionId`, `serverId`, `mode`, `startedAt`, `pid`, `envelopeSha256`, `keyFingerprint`, `launchSha256` |
| `protocol` | `seq`, `at`, `era`, `protocolVersion` |
| `server` | `seq`, `at`, `instructionsSha256`, `serverInfo`, `verdict`, `storeRef` |
| `verdict` | `seq`, `at`, `itemType`, `name`, `sha256`, `verdict`, `approvedBy`, `approvedAt`, `approvalMode`, `storeRef` |
| `state` | `seq`, `at`, `itemType`, `name` or `*`, `state`, `cause` |
| `diagnostic` | `seq`, `at`, `message` (relative paths only) |
| `end` | `seq`, `at`, `reason` (`eof`, `signal`, `child-exit`, `internal-error`, `attestation-io`) |

On an attestation write failure:

- enforce mode blocks everything: every pending, held, and later request is
  answered with `-32603` "cxbom: attestation is unavailable. Everything is
  blocked", nothing more is forwarded, and the proxy exits 70 when the
  session ends
- observe mode stops forwarding intercepted results and ends with `attestation-io`

### 8.7 Events

With `--events FILE`, C2 events go to a sidecar through a bounded, droppable queue.

- Each event carries:
  - `at`
  - `mono` (proxy monotonic seconds)
  - `proxySessionId`
  - a sidecar-local `seq`
- `--redact-sha256` replaces any string whose SHA-256 matches, or that contains
  a match, with `<canary>`.
- `tool_swapped` carries a unified `descriptionDiff` from an approved
  definition to the served one, and `oldSha256` names the approved body that
  diff prints, never an earlier served one. The diff is line by line: each
  description splits on `\n` alone, every changed line carries its own `+` or
  `-`, and up to two unchanged lines of context surround each change. Lines
  both descriptions share at the start and at the end are set aside first,
  so a change after any number of unchanged lines still shows. At most 1000
  lines of each side of what is left are compared, and a meta line says so
  when more exist. Inside one session the approved side is the last allowed
  definition, and that arm fires on every in-session change of the served
  hash: a server that swaps twice in one session gets two events for the
  same tool, not at most one, and both carry the same
  `oldSha256`. A revert to the approved body is such a change too, so it fires
  an event whose `oldSha256` equals its `newSha256` and whose
  `descriptionDiff` is empty. That is schema-valid, since `descriptionDiff` is
  an unconstrained string, and a dashboard renders it as a swap with nothing to
  show. On a session's first listing of an item there is no in-session
  predecessor, so that cold arm instead reads the approved side back out of the
  store under the pin hash. The cold arm fires at most once per tool per
  session, and only for an item whose recorded verdict is `changed`: `prior is
  None` holds until the first commit fixes the item's state line, and the
  verdict is the gate rather than a hash comparison because that comparison is
  looser than the refusal the event reports on. A client whose capabilities do
  not match `clientCapabilitiesSha256` gets `unpinned-version` (section 8.3)
  and a name one page lists twice gets `duplicate-name` (section 8.5), so
  neither gets an event: the lock never applied to either, and nothing was
  swapped. The store lookup can miss (section 5), and then no event is
  written: the verdict still blocks, the sidecar has `lock_checked` with
  `match: false` and nothing more, and one `diagnostic` line carries the
  store's own reason, which tells a body this machine never received apart from
  a store object that no longer hashes to its name. That diagnostic is the only
  attestation write in the event pass, so an attestation failure on it blocks
  the list and drops the `gate_decision` events for that tool and for every
  later tool in the page. The cold arm also withholds the event when the served
  definition is uncanonicalizable, because its text is not trustworthy enough
  to print. The in-session arm makes no such check: a served definition that
  fails canonicalization still diffs against the last allowed object, and
  because the served side then has no `description` field to read, the diff
  prints as the description being deleted rather than as the definition having
  been rejected.
- Each event's data is redacted first, then its free-text fields (`summary`,
  `reason`, `descriptionDiff`) are scrubbed of paths, the user, the host, and
  IPs, then bounded for display, then cut to the schema cap (`summary` 200,
  `launch_refused.reason` 512). `descriptionDiff` follows the same order
  one step earlier: the core hands the sidecar writer the two raw
  descriptions, and the writer redacts both, then scrubs both, and only
  then splits, diffs, marks, escapes and bounds them. A description holding
  a redacted value makes the whole field `<canary>`. The order matters
  because the line marker puts `-` or `+` in front of every line, and both
  are token characters to redaction, so a canary at a line start is matched
  only before a marker exists. The display bound prints text the server
  chose: at most 48 lines of at most 256 characters, a longer line cut with
  ` \ line cut` and a longer diff ending in one line counting the rest, and
  every character outside printable ASCII, and every backslash, escaped as
  `\u{XXXX}`. A line printed from a description starts with `+`, `-` or a
  space, the proxy's own markers carry an unescaped `\`, and a description
  line that would render as `---` or `+++` has its first character escaped,
  so a description cannot print a line or a marker that reads as the
  proxy's. Two descriptions that differ only in scrubbed text print the two
  headers and no hunk, never an empty diff. An identifier field
  (`serverId`, `tool`, `method`, `rpcId`) is never rewritten in part. One
  the scrubber would change is replaced whole with `<withheld>`.
- A startup refusal of the entry or a launch item writes one `launch_refused`
  line (C2 1.2.0) with `proxySessionId` `null` and `localSeq` 0 (section 8.1
  step 2). Any number of them may appear in one sidecar file.
- `mono` restarts near 0 in every proxy process, so it orders events only
  within one session. The J2 collector orders a real session's lines by
  `(proxySessionId, mono)`, places a null-session `launch_refused` line by its
  wall-clock `at` with ties broken by file order, and assigns C2 `seq` and `t`.
- The proxy counts dropped events by construction: every event handed to the
  sidecar, minus every line confirmed on disk whole with its newline. A full
  queue, a failed or short write, an unserializable event, and whatever the
  writer has not confirmed when the sidecar closes all count, with no path
  counting itself. A short write is never resent. The only repair is the one
  missing newline, which turns a fragment into either a whole line (its event
  is delivered) or a refused line (its event is dropped). The count can be
  high by one line a stalled write lands after the close, never low.
- A session with `--events` logs one attestation `diagnostic` line,
  `sidecar events dropped: N`, right before `end`, with 0 included. A log
  that has neither that line nor `end` was cut short. A startup refusal opens
  no attestation log, so a `launch_refused` line that fails to land is counted
  but recorded nowhere. The refusal still reaches stderr and exit code 2.

### 8.8 Shutdown

- **On agent EOF or `SIGTERM` or `SIGINT`:**
  1. Close the sidecar, waiting at most 1.0 s for its writer, write the drop
     count (section 8.7), then write `end`. `SIGTERM` and `SIGINT` are held
     off for this step, so a client that closes stdin and sends `SIGTERM`
     2.0 s later (the MCP Python SDK's `stdio_client`) still gets both lines.
  2. Close the child's stdin.
  3. Wait 1 s, send `SIGTERM` to the group, wait 1 s, send `SIGKILL`.
- **Exit codes:** the child's code, 2 for startup refusals, 70 for an internal
  error (which also writes `end`).

## 9. Emitter library

### 9.1 Modes and token accounting

**Ids mode is the default and is required for the demo.**

- The emitter tokenizes each part (scaffold and each component) separately and
  concatenates the ids. The application sends exactly `asm.token_ids()` to a
  completion endpoint that accepts token ids.
  - llama.cpp `/completion` accepts an array prompt.
  - vLLM accepts `prompt_token_ids`.
- Boundaries are exact by construction, so no token is shared between parts.
- `server_bos` states whether the endpoint prepends BOS. The emitter includes
  BOS in `asm.token_ids()` itself and requires `server_bos=False`, so the ids
  sent equal the ids recorded.
- `emit(..., sent_ids_sha256=)` must equal `sha256(asm.token_ids())`.

**Text mode is supported for applications that must send text.**

- `calibrate=endpoint_tokenize_ids` must use the same `add_special` setting as
  the completion call.
- At construction, a probe compares id sequences, not counts. The probe covers
  every marker followed by word-initial samples, a leading space, a leading
  newline, and each component class.
- `emit(..., endpoint_ids=)` compares id sequences exactly.
- Cache-reduced usage counts are rejected.

**Recording.** The `content.tokenCount` glossary entry records:

- the tokenizer sha256
- the tokenizers version
- the mode
- the serving implementation
- the id-sequence sha256

`sessionSummary.templateOverheadTokens` includes BOS.

**Attribution in text mode.**

- A token whose id is a template marker is always overhead.
- Any other token overlapping a component goes to the component with the
  largest overlap. Ties go to the earlier part.
- A token split between two components is attributed by the same rule, and the
  number of split tokens is recorded in the glossary.

**Reference reproduction** (test): the ATACE reference layout, built with
`sep("\n\n")` joiners in text mode on Phi-3, must give 46192 component tokens,
13 overhead, and 46205 total.

### 9.2 API

```python
from cxbom import (Assembly, ModelInfo, AgentInfo, ControlLayer, TrustModel,
                   load_tokenizer, session_from_meta)

asm = Assembly(
    model=ModelInfo(family="phi", version="Phi-3.5-mini-instruct", provider="Microsoft",
                    revision="2fe192450127e6a83f7441aef6e3ca586c338b77",
                    context_window_max=131072, architecture_type="transformer-decoder"),
    tokenizer=load_tokenizer("tokenizer.json", config="tokenizer_config.json",
                             expected_sha256="9e2ae3d6..."),
    template_family="phi3",
    mode="ids",
    server_bos=False,
    agent=AgentInfo(id="demo-agent", name="Demo agent", version="1.0", operator="example-org",
                    environment="testing", deployment_id="deploy-demo"),
    trust_model=TrustModel.three_ring(),
    control_layers=[ControlLayer(layer_id="tool-execution", designation="Tool Execution",
                                 description="MCP proxy with signed pins",
                                 owasp_coverage=["LLM04"], coverage_gaps=[])],
    lock="cxbom.lock",
    scanner=None,
)
fetch_session = session_from_meta(tools_list_result)   # _meta["org.cxbom/proxySessionId"]
asm.observe_session("fetch", fetch_session)   # always, so a blocked tool is reported even when nothing from the server is assembled

asm.marker("system")
asm.system_prompt("cc-001", text=system_prompt)
asm.sep("\n")
asm.server_instructions("cc-002", server_id="fetch", proxy_session=fetch_session)
asm.sep("\n")
asm.tool_definition("cc-003", server_id="fetch", name="fetch", proxy_session=fetch_session)
asm.marker("end")
asm.marker("user")
asm.user_turn("cc-004", text=user_text, turn=1)
asm.marker("end")
asm.marker("assistant")

ids = asm.token_ids()
record = asm.emit(session_id="sess-042", turn=1, inference_index=0,
                  sent_ids_sha256=sha256_of(ids))
```

- **Required inputs.** No defaults except `TrustModel.three_ring()` and
  `scanner=None`. A missing field raises.
- **Markers.**
  - `marker(role)` emits the family's marker for that role, from `templates.py`.
  - A family table lists each marker as a string and its token ids. Special-token
    and plain-text markers are both allowed, including role text such as
    `<|im_start|>system\n`.
  - The table is pinned by the `chat_template` SHA-256 from
    `tokenizer_config.json`, and a mismatch raises.
  - Families shipped: `phi3`, `qwen3` (including the `<think>\n\n</think>\n\n`
    block when thinking is off), and `olmo2`.
  - qwen3 also ships `tool_response` and `tool_response_end`. A tool result
    turn is `marker('tool_response')`, the `tool_result` component,
    `marker('tool_response_end')`, `marker('end')`, which writes exactly what
    the family's template writes for a tool message. `tool_response` opens the
    `user` region. `tool_response_end` is scaffold and closes the wrapper
    only. Between `marker('tool_response')` and `marker('end')` the parts are
    exactly one `tool_result` component and then `marker('tool_response_end')`,
    and every other sequence is refused. So the wrapper needs its tool result
    before the close, refuses a second component, a component of any other
    method, and a `sep` on either side of the close, and cannot be left open
    when `marker('end')` arrives. It also takes one wrapper per open region: the
    template's second-consecutive tool message writes a bare
    `\n<tool_response>\n` with no role text, and the table carries no marker for
    that shape, so a second wrapper inside an open region is refused. A second
    wrapped turn after `marker('end')` is allowed, and is what the template
    writes for a tool message that does not follow another one. The kind rule is
    load-bearing rather than tidiness: a `user_turn` inside the wrapper produced
    a prompt byte-identical to the `tool_result` one, `ids_sha256` included,
    while the record called the span a ring-2 first-party user turn instead of a
    ring-1 third-party tool result, and both records passed validation.
  - The added tokens a wrapper or block marker contributes on top of its role
    text (`<tool_response>`, `</tool_response>`, `<think>`, `</think>`) are not
    role or turn markers, so section 13 ranks them in content as other special
    tokens.
  - `inline_marker(name)` appends one of the family's inline tags: a single
    added token the template writes inside a turn rather than around one. qwen3
    ships `tool_call` and `tool_call_end` (`<tool_call>` and `</tool_call>`, ids
    151657 and 151658), which its template writes in the system prompt's tool
    instructions. The caller names the tag and the table supplies the id, so no
    caller can place an arbitrary id. The tag is overhead: it adds no component
    and no `contextComponents` entry, its id counts in `templateOverheadTokens`,
    and its text sits in `text()` where its id sits in `token_ids()`. It is
    accepted only in the `system` region, which keeps it out of the `user`
    region a `<tool_response>` wrapper occupies, and a family with no tag of
    that name refuses (phi3 has none). `marker` cannot reach an inline tag, and
    in content section 13 ranks one as an other special token. A table's inline
    tag must be one added token that absorbs no whitespace, and the table is
    refused at load otherwise.
  - A role region opens only through `marker`.
- **`sep(text)`** accepts whitespace only. It is overhead.
- **Positions** are derived from the open region and never taken from the caller.

**Component methods:**

| Method | type / subtype | ring / tier | positionInContext |
|---|---|---|---|
| `system_prompt` | system-prompt / primary-operator-instruction | 0 / operator | `prepended` |
| `server_instructions` | tool-definition / external-mcp-server (internal-operator-authored when first-party) | 1 / agent | `tool-schema-block` in the system region, else `tool-definitions-<role>-region` |
| `tool_definition` | tool-definition / as above | 1 / agent | as above |
| `retrieved_document` | retrieved-document / rag-chunk | 1 / agent | `retrieved-content` |
| `tool_result` | tool-result / external-api-response | 1 / agent | `tool-result-turn-<n>` |
| `model_output` | retrieved-document / memory-injection, origin `model-generated` | 1 / ring-1-derived | `model-output-turn-<n>` |
| `user_turn` | user-turn / conversational-query | 2 / user | `user-turn-<n>` |

**Generated ids, `model_output_ids(cid, ids=, turn=)`:** the ids a model
generated re-enter verbatim, because re-tokenizing their decoding can give
different ids (J2 premortem K13). On the pinned qwen3 tokenizer the ids for
`<`, `tool`, `_call`, `>` decode to `<tool_call>`, which re-encodes to the added
token 151657, and the plain spelling of `<|im_start|>` re-encodes to the role
marker 151644. The component is a `model_output` in every record field, and
its text is the decoding of the ids.

- Pass the ids exactly as the server returned them. A last id equal to the
  first id of the family's `marker('end')` (qwen3 `<|im_end|>` 151645, phi3
  `<|end|>` 32007) is the model's turn close. It stays out of the component,
  and the caller's `marker('end')` writes that same id back, so the generation
  sits in the next prompt as one unbroken run. qwen3 may also stop on
  `<|endoftext|>` 151643, which llama.cpp's end-of-generation set holds: it is
  dropped the same way, and `marker('end')` writes the template's `<|im_end|>`
  in its place, as the Qwen3 template does after every assistant turn. Every
  other added token in the final position is refused, phi3's `<|endoftext|>`
  included. A generation cut off before any stop id enters whole. Either way the
  prompt and the record equal what `model_output(text)` gives for any text
  `model_output` accepts that encodes to the same ids. `model_output` refuses
  text that opens with whitespace a marker would absorb, and the ids path
  accepts the generated ids for it.
- The added tokens are an allowlist, resolved from the pinned tokenizer by
  content. Every added or special token is refused, flagged special or not
  (qwen3's `<|fim_prefix|>` to `<|file_sep|>`, phi3's `</s>`), except the
  family's inline tags anywhere in the body, because the template writes them
  in an assistant tool call, and a ruled stop as the last id. A stop on any
  other added token therefore fails loud instead of entering as content.
- Also refused before anything is appended: ids that are not a list or tuple
  of ints, an id outside the pinned vocabulary, ids whose decoding holds a
  replacement character (a cut inside a multi-byte character, or a real
  U+FFFD the model wrote, which the decoding cannot tell apart), and ids
  anywhere but right after the marker that ends the generation prompt in the
  `assistant` region.
- Generated ids can spell a control token in plain pieces. The special-token
  finding keeps its severity, and its description then says the component's
  ids do not carry the token and re-tokenizing the text would. In text
  content, every added token now counts as an other special token, flagged
  special or not.
- 0.3.0 has no component field for an id hash, and the schema is not changed for
  it. The record carries `ids_sha256` of the ids as passed in the
  `content.sha256` glossary entry, as `<cid>=<hex>` followed by the stop id
  that ended the generation (for example `stopped on 151643 <|endoftext|>, turn
  closed by the template with 151645 <|im_end|>`), the same way
  `content.tokenCount` carries the prompt's id-sequence hash.

**Text sources for `tool_definition` and `server_instructions`:**

- Both take `proxy_session` explicitly.
- In state `allowed` and bound: text comes from the store object the verdict
  references, through the signed entry's renderer.
- In any other state (unverified, changed in observe mode, no lock, or no
  session): the caller must pass `text=` with the exact bytes the model receives.
  The component is recorded with `serverChecksumVerified: false`.
- `content.sha256` is always computed over the exact bytes assembled.

**Renderers** (`renderers.py`) form a closed registry, named by the signed entry:

- `jcs`: RFC 8785.
- `json-indent2`: sorted keys, indent 2.
- `wire`: exact wire bytes. Ignored pointers are replaced with their approved values.

The rendered text must parse back to the attested object, with ignored pointers
at their approved values.

**Other rules:**

- Empty or whitespace-only component text raises.
- **Special tokens.** The component's own text is scanned against the family
  table and the tokenizer's special tokens, by string and by id.
  - role or turn marker: `high`
  - BOS or EOS: `medium`
  - other special token: `medium`
  - Each carries audit flag `SPECIAL_TOKEN_IN_CONTENT`.

### 9.3 Binding

- `tool_definition` and `server_instructions` capture
  `(proxySessionId, seq, sha256, storeRef)` when they are called.
- At `emit`, a bound item must pass all of the following. Any failure records it
  as unverified with a `tool-definition-binding` finding, and `emit` does not raise.
  1. The log is under the user state dir.
  2. A non-blocking `flock` on the log fails, meaning a live proxy holds it.
  3. `seq` is contiguous.
  4. There is no `end` line.
  5. `envelopeSha256` equals the envelope the emitter verified.
  6. The current state from `state.py` is still `allowed` with the captured `sha256`.
- If the named log does not exist, `emit` raises.

### 9.4 Record mapping (existing 0.3.0 fields only)

| State at emit | Fields |
|---|---|
| `allowed` and bound | `serverChecksumVerified: true`, `serverChecksum`, `sessionId: <proxySessionId>`, `uri: "cxbom-attest:<proxySessionId>#<seq>"`, `retrievedAt: <verdict at>`, `authorizedBy: "unverified-approver:<role>:<approvalMode>:signer-<fingerprint16>"`, `serverVersion: <serverInfo.version from the server line>`, `serverVersionPinned` per the allowlist below |
| Any other state or failed binding | `serverChecksumVerified: false`, `serverVersionPinned` per the allowlist |
| Blocked this session, never assembled | No component. Finding `tool-definition-blocked`, status `mitigated`, `affectedComponents: []`, `evidence.componentId: "session"` |
| `changed` assembled in observe mode | Unverified fields, plus finding `tool-definition-change` |

- **`serverVersionPinned` allowlist.** True only for:
  - `uvx pkg==X`
  - `npx pkg@X.Y.Z` (exact)
  - `pipx run pkg==X`
  - `docker ... img@sha256:...`
  - a local server whose files or trees are all pinned

  Every other launcher in the section 6 runner table (`uv tool run`,
  `npm exec`, `bunx`, `bun x`, `pnpm dlx`, `pnpx`, `yarn dlx`, `podman`,
  `corepack`), and the forms above with any other argv, gives false even when
  files or trees are pinned, because the runner fetches what it runs. The
  proxy's runner grammar and this check read one shared runner set.
- **Integrity** never changes `toolDefinitionTrustInversion.mitigationStatus`.
  That field is `full` only when a registered trust label is present and verified
  (section 9.5). Otherwise it stays `none`.

**Glossary entries** (fixed text; the bracketed parts are filled per record):

| Field | Entry |
|---|---|
| `source.serverChecksumVerified` | Definition hash matched a signed pin in a live, bound proxy session. Server code and dependencies are not verified. The attestation log is integrity-checked, not authenticated, against same-user processes |
| `source.authorizedBy` | Approver role, approval mode, and the fingerprint of the signing key. Not an authenticated person |
| `content.tokenCount` | [tokenizer sha256, tokenizers version, mode, serving implementation, id-sequence sha256, split-token count] |
| `content.contextualSharePercent` | Share of component tokens, excluding template overhead. Not a model-weight share |
| `metadata.session.id` | `<session_id>/<turn>/<inference_index>`. One record per inference. `contextWindowTokensUsed`, `startedAt`, and `endedAt` are per inference |
| `sessionSummary.sessionAuditClean` | False unless a scanner callback filled every security field |
| `byType.modelOutput` | Model-generated re-entrant content (ring-1-derived), recorded as retrieved-document or memory-injection under the frozen enum |
| `sanitization.trustLabel` | Registered boundary id. Changes assembly structure, not model weighting |
| `source.serverVersion` | Server self-reported and not authenticated. `serverVersionPinned` refers to the launcher's package argument, not to this value |

- **`notCollected` per component**, unless the `scanner` callback supplies the value:
  - `injectionRiskRating`
  - `sanitization.scanner`
  - `sanitization.scannerVersion`
  - `sanitization.scannedAt`
  - `containsPII`
  - `containsCredentials`
  - `containsSecretsOrKeys`
- **Missing-control findings.** One per group, open:
  - injection and scanner fields: `LLM01`, `CWE-1427`
  - PII: `LLM02`, cweRef `""`
  - credentials and secrets: `LLM02`, cweRef `""`
- **Audit summary.**
  - `sessionAuditClean` is true if and only if no finding is open.
  - `auditCleanBlockers` equals the set of open finding ids.
  - `auditTrailComplete` is false when any tool is unverified.
  - `consistency.py` enforces all three.
- **Identity.**
  - `version` is always 1.
  - `serialNumber` is a fresh `urn:uuid`.
  - Tool components carry `label: "mcp-tool:<serverId>/<name>"`.
- **`session_totals(records)`** deduplicates by
  `(type, positionInContext, content.sha256)` and reports the worst verification state.
- **`diff`** pairs tool components by label and other components by
  `(type, positionInContext)`.

### 9.5 Trust labels

- `trust_label=` on `tool_definition` and `server_instructions` names an id from
  the boundary registry in `renderers.py`.
- The component text is `open(id) + rendered + close(id)`, and `content.sha256`
  is over the wrapped text.
- `approve` and `emit` reject any definition containing a registered open or
  close marker.
- The emitter sets `sanitization.trustLabel` to the registry id.
- `gate` with `--store` verifies the stored rendered text equals the wrapped
  form. A label that fails this check is `unverifiable-integrity-claim`.

## 10. Findings (`findings.py`)

A test proves every template passes the vendored validator and resolves in the catalogs.

| Finding | title | severity | category | cweRef | owaspRefs | status |
|---|---|---|---|---|---|---|
| Trust inversion | from ATACE detector | high | trust-inversion | ATACE | ATACE | open |
| Definition changed (observe) | MCP tool definition changed since approval | high | tool-definition-change | CWE-345 | LLM04 | open |
| Definition blocked (enforce) | MCP tool definition blocked before assembly | low | tool-definition-blocked | CWE-345 | LLM04 | mitigated |
| Binding failed | Tool integrity could not be bound to a live proxy session | medium | tool-definition-binding | CWE-345 | LLM04 | open |
| Special token, role or turn | Chat role marker inside non-scaffold content | high | special-token-injection | CWE-1427 | LLM01 | open |
| Special token, other | Special token inside non-scaffold content | medium | special-token-injection | CWE-1427 | LLM01 | open |
| Missing control | Security fields not collected: <group> | low | missing-control | section 9.4 | section 9.4 | open |

`formalRef` is `""` except for the ATACE template.

## 11. CLI

```
cxbom keygen | trust add KEY.pub | trust revoke FP --after DATE | init
cxbom approve (7) | proxy (8)
cxbom validate RECORD... [--store DIR]
cxbom gate RECORD... [--lock PATH] [--bundle DIR --trusted-key FINGERPRINT...]
           [--fail-on unverified|inversion|any|any-strict] [--allow-accept-flag]
cxbom scan [PATH] | guard [PATH]
cxbom diff OLD NEW | check-drift [--lock PATH] [--i-trust-lock-commands]
cxbom attest prune --keep N | attest bundle RECORD... --out DIR
```

Slice 1 ships `keygen`, `trust add`, `init`, `approve`, and `proxy`. Every other
command in this section is a next-plan feature (section 15), settled here in
design and absent from `cxbom --help` and from the parser until it is built.

- **`init`**
  - writes `lockScope`
  - gitignores `.cxbom/`
  - records the realpath and SHA-256 of the `cxbom` entry point and its
    interpreter in `<config>/wrapper.json`
- **`validate`** runs the vendored validator plus `consistency.py`. With
  `--store`, it recomputes `serverChecksum`, `content.sha256`, and trust-label wrapping.
- **`gate`**
  - Re-runs the vendored detector and never trusts `detected`.
  - Recomputes `thirdParty` from the signed `firstParty`.
  - Verification:
    - `--bundle` requires `--trusted-key` fingerprints, which come from CI
      configuration outside the bundle. Keys inside a bundle are used only when
      their fingerprint is in that set.
    - Bundle mode reports "consistent, not authenticated" and cannot check liveness.
    - Without evidence, every integrity claim counts as unverified.
  - **`--fail-on unverified`** (default) fails on any of:
    - an unverified tool or instructions component, first-party included
    - `accept-flag` without `--allow-accept-flag`
    - open `tool-definition-change`, `tool-definition-binding`, or `high`
      `special-token-injection`
  - **`--fail-on inversion`** additionally fails on every detected inversion
    without a verified trust label. It is a CI gate over emitted records. The
    demo never runs it, because every `jcs`-rendered tool in the system block
    is an inversion by design (section 16).
  - **`any`** fails on any open finding except `missing-control`.
  - **`any-strict`** fails on any open finding.
- **`scan`** reads `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, and
  Claude Code project settings. It reports:
  - servers whose command does not resolve to the `wrapper.json` realpath and hash
  - relative or workspace-resident wrapper commands
  - wrapper flags other than `--server-id`, `--lock`, `--events`, `--redact-sha256`
  - any `env` key outside `LANG`, `LC_ALL`, `TERM`
  - wrapped commands differing from the signed lock
  - unsigned or untrusted envelopes
  - launches outside the pinned allowlist
  - home paths
  - a tracked `.cxbom/`

  It never starts a server.
- **`guard`** runs `scan` and exits 1 on findings. It is detection only.
  - Install it in a user-level Git hooks path (`core.hooksPath` in the global
    config), never a tracked hooks directory.
  - Git `post-checkout` and `post-merge` hooks cannot abort.
  - No host pre-launch hook is claimed.
- **`check-drift`** runs a server only after the section 8.1 checks. Unattended
  runs require `--i-trust-lock-commands`. It is advisory.
- **Exit codes:** 0 pass, 1 findings, 2 usage or I/O error, 70 internal
  error. An internal error prints `cxbom: internal error (TypeName)` and no
  exception text, so no path reaches the terminal.

## 12. Packaging and distribution

- **Build.**
  - Backend `hatchling==1.32.4`, built with a hashed build-constraint file and
    `SOURCE_DATE_EPOCH` set to the commit time.
  - The published wheel is built in CI on Linux. The Mac verifies it and signs it.
  - Tool version 0.3.0.
  - Authors `ATACE Working Group`, no email. The only URL is `https://cxbom.org`.
  - LICENSE is Apache-2.0 for the code. NOTICE carries:
    - the ATACE credit
    - the MITRE CWE terms-of-use notice
    - the ATLAS notice
    - the OWASP attribution
    - the tokenizer fixture notices (Phi-3.5 MIT, Qwen3-8B Apache-2.0)

    The catalog license fields in `SOURCES.json` are corrected against each
    source's actual terms before release.
- **Install before the review decision.** `cxbom.org/install` shows:

  ```
  minisign -Vm cxbom-requirements.txt -P <public key>
  pip install --no-deps --require-hashes --only-binary :all: -r cxbom-requirements.txt
  pip check
  ```

  - `cxbom-requirements.txt` holds the dependency lock plus
    `cxbom @ https://cxbom.org/dist/cxbom-0.3.0-py3-none-any.whl --hash=sha256:...`.
  - A minisigned `SHA256SUMS` covers every file.
  - There are separate core and emit requirement files.
  - Environments with their own lock add the same direct reference to their lock.
    They never add `cxbom` by name.
  - Every lock installs with `--no-deps`, because pip 22.0.2 (Ubuntu 22.04)
    re-resolves extras against the live index even under `--require-hashes`.
    `pip check` then proves the installed set is complete.
  - The emit lock installs `tokenizers` without `huggingface-hub`. The emitter
    loads a pinned local file and never downloads, so in an emit install
    `pip check` reports exactly one line, `tokenizers <version> requires
    huggingface-hub, which is not installed.`, and `scripts/verify_env.py`
    accepts that line and no other.
  - The package runs from files on disk. The vendored validator reads its data
    through a filesystem path, so `import cxbom` from a zip archive raises
    `ImportError`.
- **Signing key.**
  - minisign with a passphrase, generated and used under a separate macOS user
    account, or on removable media, with no agent tooling.
  - A revocation statement is signed in advance and kept offline.
  - The slide shows only the public key and `cxbom.org/install`.
  - The install page states the key without naming where else it appears.
  - The site never mentions the talk or arXiv, and an `anon_check` string test
    enforces this.
- **Anonymity scan.** `anon_check.py site DIR` decompresses `.whl`, `.tar.gz`,
  and `.zip`, scans every member plus the tar `uname` and `gname`, and scans every
  published file including locks and signatures.
- **PyPI placeholder `cxbom==0.0.1`.**
  - Built with hatchling in reproducible mode and scanned before upload.
  - The account uses a cxbom.org address that receives mail.
  - Hardware-key 2FA. The registrar has lock and 2FA on.
  - The placeholder is yanked at release.
- **Decision branches.**
  - Early reject on Oct 6: the owner decides by Oct 13 whether anonymity continues.
  - Acceptance on Dec 3: PyPI, GitHub release, Sigstore.

## 13. Failure modes

| Failure | Behavior |
|---|---|
| `HOME` differs from `pw_dir`, or insecure permissions on a cxbom dir | Exit 2 |
| Lock missing, unsigned, untrusted, rolled back, expired, or invalid | Proxy exits 2. The emitter records tools as unverified |
| Launch mismatch (argv, binary, interpreter, files, trees, env) | Exit 2 before spawn, naming the item. An argv mismatch names the first differing index and its escaped value. A binary or interpreter mismatch says to re-run `cxbom approve` for the server (`--rebind-binary` is a next-plan feature) |
| Strict-parse failure, id mismatch, late response after cancel | Sections 8.2 and 8.4 |
| Uncanonicalizable item, or bad ignored-leaf value | Blocked |
| Era ambiguity, or capabilities mismatch | Section 8.3 |
| Attestation write failure | Enforce mode blocks everything. Observe mode ends with `attestation-io` |
| Proxy killed | The log is already written ahead. `flock` is released, so bindings fail closed. The watchdog kills the child's group |
| Id or text calibration mismatch | The `Assembly` constructor raises |
| Binding failure at emit | Unverified, plus a `tool-definition-binding` finding |

## 14. Testing

**Fake MCP server** (dual-era, `tests/fake_mcp_server.py`). Scriptable to:

- swap a definition, change instructions, or emit `list_changed`
- paginate, and support cursor re-fetch
- send string-typed ids, server-sent cancels, and late responses
- send invalid UTF-8, duplicate keys, lone surrogates, `1e400`, integers above
  2^53, and lines over 64 MiB
- send batches
- return MRTR sampling on all three methods
- set `ttlMs`
- supply duplicate `org.cxbom/*` keys
- change an ignored leaf's type
- ignore `SIGTERM`, spawn a grandchild, and require environment variables
- vary its tool list by declared capabilities
- answer `server/discover` with a non-modern error

**Security tests:**

- `HOME` or `XDG_*` redirect is refused.
- A planted `uv.toml` under a fake home is unreachable.
- Trust manifest tampering.
- `trust add` without the passphrase.
- Rollback below the high-water mark.
- Expired `allowObserve`.
- Accept-flag without `allowAcceptFlag`.
- ANSI, bidi, and tag characters in review.
- No TTY means no signing.
- Wrapper realpath mismatch in `scan`.

**Proxy tests:**

- every interception row and state transition
- era latch with a dual-era client against a legacy server (expected: tools allowed)
- modern re-list `_meta` copying
- byte fidelity of splices
- a 1,000-call load with no lost attestation line
- shutdown on Linux and macOS: proxy SIGKILL, group SIGKILL, host restart, then
  confirm no child remains
- after proxy SIGKILL, a non-blocking `flock` succeeds within 1 s

**Emitter tests:**

- Ids-mode token equality end to end against a fake completion endpoint.
- Text-mode id-sequence calibration, including Phi-3 rstrip absorption and the
  `▁` prefix after markers.
- Reference reproduction: 46192, 13, 46205.
- Marker tables for phi3, qwen3, and olmo2.
- Adjacent tool definitions (`}{`).
- Unverified and observe-mode components use caller text.
- Trust-label wrapping and escape rejection.
- No ATACE reference constants in output.
- Every record passes the vendored validator and `consistency.py`.
- A record with timestamp `"yesterday"` fails.

**Contract tests:** the C2 merged stream, and the C3 envelope, lock, and
attestation schemas.

**CI:**

- Linux on Python 3.10 and 3.13 on every push.
- arm64 Linux and macOS arm64 on `main` and on `workflow_dispatch`.
- Load and property suites nightly.
- Reproducible wheel build and hash comparison.
- `anon_check site` on the release directory.

## 15. Delivery

Today is 2026-09-24. Scope is full (owner decision). The slices are ordered by
the demo path. Anything in the Oct 10 row that is not green by Oct 13 moves to
"Not covered in this version" and ships documented.

| Date | Deliverable |
|---|---|
| Sep 24 to 25 | **Owner:** GoDaddy parking off, PyPI name reserved |
| Sep 28 | Contract commit on `main`: C3 2.0.0 (envelope lock, attestation) and C2 1.1.0 (sidecar with `mono`; `cxbom_emitted` and `component_assembled` emitted by the emitter; protocol-correct example). `Assembly` signature frozen |
| Sep 30 (Jetson answers, blocking) | J2 model from a `templates.py` family. Serving with token-id prompts (llama.cpp `/completion` array or vLLM `prompt_token_ids`). MCP client and whether it is dual-era. JetPack and agent-container Python (3.10 or newer, separate from the serving container). Rug-pull trigger in-process (after the first `tools/list`, swap and emit `list_changed`). J1 and J2 in separate memory windows. uv, node, and python pinned by version and digest in J2 images. A demo-only signing key: the lock is signed on the Mac and copied to the Jetson, and the Jetson holds the public key only |
| Oct 3 | **Slice 1 (Linux, legacy era, tools only):** `paths`, `jsonstrict`, `canonical`, `signing` (keys, envelope, manifest, high-water mark), `lockfile`, `store`, `state`, `attestation`, `launch` (Linux watchdog), `relay`, `proxy` (enforce and observe, re-listing, era latch), `approve` with `--accept` only, `Assembly` in ids mode with every component method, the `jcs` renderer, the phi3 table, `emit` with binding, `findings`, `consistency`, and the vendored validator. Wheel and requirements installed on the Jetson from the private repo |
| Oct 7 | **Go/no-go:** J2 runs the rug-pull through the real proxy on the Jetson, in enforce, in observe, and with no proxy (gate off), with records. `demo/gonogo.py` must print GO first: the three token counts are equal, every lock entry is valid across the recording window, launchers and interpreters sit on the trusted search path, the agent user has a passwd entry, and every proxy starts in enforce and `notes` in observe. `cxbom` must import from the installed distribution, not from the checkout. The go file names every core check (`account`, `installed-wheel`, `wheel-sha256`, `token-counts`) plus one `lock-`, `launch-` and `proxy-` check per server, and a go file missing any of them is refused. **Fallback A:** live proxy and live emitter with a scripted model stub (`demo/scripted_model.py`) replaying captured outputs through the same ids interface, labeled "scripted model outputs" on screen for the full take, and the take sets `run_started.synthetic: true`. **Fallback B (proxy not ready):** pre-recorded proxy run, labeled |
| Oct 10 | Modern era, prompts, resources, and templates. Sampling, MRTR, capability stripping, `ttlMs`. Interactive review with `display.py`. `wire` and `json-indent2` renderers. The olmo2 table. Text mode. Trust labels. macOS watchdog. Special-token findings. Full relay suite. CI matrix |
| next plan | J2 end to end. `scan`, `guard`, `gate` with bundles, `attest bundle`, `rebind-binary`, `trust revoke`, `--first-party`. Started as soon as slice 1 lands, not date gated |
| Oct 16 | Distribution: CI-built reproducible wheel, requirements files, minisign signatures, site live with the install page |
| Oct 19 | Final takes. **Claims gate:** every section 16 and section 17 sentence maps to a passing test id, or the pre-written reduced-claim slide is used. `check-drift` is green before each take |
