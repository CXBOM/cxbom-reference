# CxBOM

Owner: ATACE Working Group. Status: preview release 0.3.0.

CxBOM (Context Bill of Materials) records everything assembled into an LLM
agent's context window before inference: each component, its trust ring, and
its provenance. It extends CycloneDX 1.6.

This repository holds the `cxbom` tool and its tests, the CxBOM specification and
schemas in `spec/`, the interface contracts in `contracts/`, and the source of the
cxbom.org site. The tool's design is `docs/design/tool.md`.

`cxbom` has two parts:

- `cxbom proxy` sits between an MCP client and a stdio MCP server. It blocks
  tool definitions that changed after a human reviewed and signed them, and it
  refuses to launch a server whose command, launcher binary, pinned files, or
  environment differ from the signed ones.
- The `cxbom` emitter library writes one CxBOM 0.3.0 record per inference,
  bound to the live proxy session that verified each tool.

## Install

cxbom needs Python 3.10 or newer on Linux or macOS. Every install is
hash-locked and runs pip with `--no-deps --require-hashes --only-binary :all:`,
then checks the result. Ubuntu 22.04 ships pip 22.0.2, which re-resolves
extras against the live index even under `--require-hashes`, so a plain
install from a lock can drift or fail there.

From a clean checkout of the commit you want:

```
python3 scripts/install_cxbom.py download --wheelhouse wheelhouse \
  --pip-lock requirements/pip-build.txt
python3 scripts/install_cxbom.py build --wheelhouse wheelhouse --out dist \
  --pip-lock requirements/pip-build.txt
python3 scripts/install_cxbom.py install --wheelhouse wheelhouse \
  --wheel dist/cxbom-0.3.0.dev0-py3-none-any.whl --venv cxbom-venv --emit
```

- `download` is the only step that uses the network. It fetches every file the
  locks in `requirements/` name, for the interpreter that runs it, and checks
  each hash. `--pip-lock requirements/pip-build.txt` adds the pip that `build`
  needs, so `build` stays offline. Run `download` with the Python that will run
  cxbom.
- `build` builds the wheel offline and prints its SHA-256. Two machines that
  build the same package sources get the same bytes. Pass `--expect-sha256`
  with the other machine's value to refuse a different wheel.
- `--pip-lock requirements/pip-build.txt` on `build` is required, not optional.
  `build` makes a throwaway venv, and a new venv keeps whatever pip its
  interpreter bundles: on Ubuntu 22.04 that is pip 22.0.2, and any image built
  on it starts there too. Building needs pip 24.0 or newer. The build step
  refuses an older pip with one line rather than failing inside the build
  backend, so without this flag the build refuses wherever the interpreter
  bundles an older one. `--pip-lock` force-installs the hash-pinned pip from
  that lock into the build venv and refuses unless `pip --version` then reports
  it. Installs never build, so they stay proven on Ubuntu 22.04's own pip
  22.0.2, and the step above leaves the flag off. CI passes `--pip-lock
  requirements/pip.txt` on its install steps instead, to force that exact pip
  rather than trust whatever the runner image ships.
- `install` creates a new venv and installs the core lock, the emit lock with
  `--emit`, and the wheel by hash, all with `--no-deps --require-hashes
  --only-binary :all: --no-index`, then runs `scripts/verify_env.py`. Leave
  `--emit` off for a proxy-only install.
- In an emit install `pip check` reports one line: `tokenizers` requires
  `huggingface-hub`. That is on purpose. The emitter loads a pinned local
  tokenizer file and never downloads, so the hub library is left out.
  `scripts/verify_env.py` accepts that line and no other.
- Run cxbom from the installed venv. It refuses to run from a zip archive, and
  the go/no-go refuses a checkout import.

## Use

```
cxbom keygen
cxbom trust add teammate.pub
cxbom init
cxbom approve --server-id fetch --approver demo-operator -- uvx --with mcp==1.30.0 mcp-server-fetch==2025.4.7
cxbom approve --server-id fetch --approver demo-operator \
  --accept TOOL_SHA256 --reason "reviewed the description and schema" \
  --accept INSTRUCTIONS_SHA256 --reason "reviewed the server instructions" \
  -- uvx --with mcp==1.30.0 mcp-server-fetch==2025.4.7
cxbom proxy --server-id fetch -- uvx --with mcp==1.30.0 mcp-server-fetch==2025.4.7
```

- `cxbom keygen` creates your passphrase-protected Ed25519 signing key under
  the config directory of your account. The passphrase is read only from the
  terminal.
- `cxbom trust add KEY.pub` adds another person's public key to your signed
  trust manifest. It asks for your passphrase.
- `cxbom init` writes `cxbom.lock` with a fresh `lockScope`, adds `.cxbom/` to
  `.gitignore`, and records the realpath and hash of the `cxbom` entry point.
- `cxbom approve` starts the server, lists what it tells the model, and prints
  each tool's hash and escaped text. The first run signs nothing. Review the
  text, then run it again with an `--accept HASH --reason TEXT` pair for each
  item you approve, and type the server id when asked. Package runners must pin
  an exact version (`uvx pkg==1.2.3`, `npx pkg@1.2.3`, `image@sha256:...`).
- `cxbom proxy` runs the server behind the pins. Put it in your MCP config in
  place of the server command:

```json
{"mcpServers": {"fetch": {"command": "/opt/cxbom/bin/cxbom",
  "args": ["proxy", "--server-id", "fetch", "--", "uvx", "--with", "mcp==1.30.0",
    "mcp-server-fetch==2025.4.7"]}}}
```

`mcp-server-fetch==2025.4.7` declares `mcp>=1.1.3` with no upper bound, so an
unpinned `uvx mcp-server-fetch==2025.4.7` resolves whatever `mcp` PyPI carries
that day. That server does not bound its own dependency, and `cxbom approve`
does: every `--with` spec must carry an exact version, or the launch is
refused with `pin an exact package version`. `--with mcp==1.30.0` is that
enforcement demonstrated on the tool's own flagship example.

Pre-seeding the `uvx` cache does not rescue an unpinned invocation. If the
first resolution picked a broken `mcp` version, `UV_OFFLINE=1` against that
cache replays the same broken resolution, not a working one. Seed the cache
with the pinned argv above, not the bare one.

Observe mode forwards a changed definition and records it instead of blocking
it. The signed entry must allow it. It has no expiry unless you add
`--not-after` with a future RFC 3339 UTC time, which has no maximum:

```
cxbom approve --server-id notes --approver demo-operator --pin-tree notes-server \
  --allow-observe \
  --accept TOOL_SHA256 --reason "reviewed search_notes" \
  --accept INSTRUCTIONS_SHA256 --reason "no instructions" \
  -- notes-server/.venv/bin/python notes-server/server.py
cxbom proxy --server-id notes --mode observe -- notes-server/.venv/bin/python notes-server/server.py
```

### Local servers need a `--copies` venv

A bare launcher name resolves only on the trusted search path: `/usr/local/bin`,
`/usr/bin`, `/bin`, `/opt/homebrew/bin` on macOS, and `.local/bin` in your
account's home directory. A server you run from your own directory must sit in
a tree pinned with `--pin-tree`. If it needs packages, give it a venv inside
that tree made with `--copies`:

```
cd notes-server
python3 -m venv --copies .venv
.venv/bin/python -m pip install --no-deps --require-hashes -r requirements.txt
.venv/bin/python -m pip check
```

`approve` and `proxy` refuse a venv made without `--copies`. Its `bin/python`
is a symlink to an interpreter outside the pinned tree, and a Python binary
reads the `pyvenv.cfg` beside the path it starts from, so the launch pins accept
an interpreter only when its path and its realpath both sit inside the pinned
tree or on the trusted search path.

## Not covered in this version

`cxbom --help` prints the same list.

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

## Tests

```
python3 -m venv .venv
.venv/bin/pip install --no-deps --require-hashes --only-binary :all: -r requirements-dev.txt
.venv/bin/pip check
.venv/bin/python -m pytest -q
```
