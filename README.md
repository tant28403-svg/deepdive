# deepdive v2.0.0

Scan repos and files **before** you run or clone them.

- Static analysis (magic bytes, AST, secrets, YARA, Sigma, deobfuscation)
- Binary triage (PE/ELF/Mach-O, strings, imphash, embedded payloads carves)
- Dependency audit (OSV, lockfile integrity, typosquatting, manifest drift)
- Sandbox (opt-in): Docker or native isolation, process/network/registry/memory telemetry
- Deep mode (`--deep`): git history + SBOM export + baseline comparison
- Optional analyzers: Java, WASM, Android DEX, .NET metadata, disassembly (`--features disasm`)

## How it works

```bash
deepdive scan .                  # quick static check
deepdive scan . --deep           # + git history + dependencies
deepdive audit ./repo            # deep + optional sandbox
deepdive fetch https://github.com/user/repo --sandbox --deep
```

The scan reads files by magic bytes (not just extensions), routes them to module
analyzers, scores findings (0-100), and prints a verdict (`SAFE` / `REVIEW` /
`UNSAFE` / `BLOCK`). Sandbox output is included in JSON (`"sandbox": {...}`).

## Key flags

| Flag | Purpose |
|---|---|
| `--format text\|json\|sarif` | Report format |
| `--out file` | Write instead of stdout |
| `--deep` | Git history + dependency audit |
| `--sandbox` | Run target in a sandbox |
| `--sandbox-cmd "..."` | Your command (never invented by the tool) |
| `--sandbox-backend auto\|native\|docker\|none` | Which isolation to use |
| `--sandbox-policy strict\|network-capture\|permissive` | Isolation strictness |
| `--offline` | Skip network (use cached OSV/intel) |
| `--rules file.toml\|.yml\|.yar` | Custom rules |
| `--min-severity info` | Hidden from output only; verdict uses all |
| `--fail-on high` | Exit 2 if finding reaches this |
| `--baseline prev.json --regression` | Compare to prior report; exit 2 on new high/critical |
| `--intelligence` (future) / `--intel` (current) | Match URLs/hosts to cached threat feed |

## Sandbox (v2)

The sandbox backend picks the best available isolation:

- `auto`: Docker when installed, else native (Linux namespaces / Windows Job Objects)
- `native`: Linux `unshare` + seccomp + cgroup v2; Windows restricted token / AppContainer (stage 19 partial: job limits + registry + memory dumps work; full AppContainer/ETW not yet)
- `docker`: isolated container (`--network none`, `--read-only`, `--tmpfs /tmp` when `strict`)

When `network-capture`, a local proxy logs all HTTP/CONNECT and a fake DNS answers
`NXDOMAIN`; captured events feed `sandbox.network.*` findings (DGA, beacon, raw IP,
uncommon port, tunnel). The tool never MITMs TLS.

Self-check before trusting native isolation:

```bash
deepdive sandbox selftest --backend native --policy strict
```

## Install

```bash
git clone https://github.com/tant28403-svg/deepdive
cd deepdive
cargo build --release --features disasm,java,wasm   # full analyzers
# or just cargo build for the default set
sudo install -m 755 target/release/deepdive /usr/local/bin/
```

### Interactive guided mode

If you prefer menus over flags:

```bash
deepdive interactive
# 1. Scan a file/dir
# 2. Deep audit (git + sandbox)
# 3. Fetch remote repo
# 4. Rules / cache
# 5. Sandbox selftest
# 6. Cache update/clear
# 7. Exit
```

It prompts for path, format (`text`/`json`/`sarif`), sandbox (`y`/`n`), command, and output file, then prints the exact command it would run.

Example session (choice 3 — fetch a repo):

```bash
deepdive interactive
# Choose 3
# Repo URL: https://github.com/user/repo
# Keep clone at ./repo? y
# Format [text]: json
# Sandbox? y
# Sandbox command (blank = true):
# Output file (blank = stdout): report.json
# Confirm run? y
```

The result is saved to `report.json` (or stdout if left blank) with `schema_version` 2.0, `verdict`, `findings`, and `sandbox` telemetry included. You can also copy the printed command and run it directly in your shell.

Quick direct command (same result, faster):

```bash
deepdive scan ./repo --format json --offline --deep --sandbox --out report.json
```

### If `deepdive` command not found after install

```bash
# Confirm build exists
ls -la ~/deepdive/target/release/deepdive
which -a deepdive

# Rebuild if pull was blocked by Cargo.lock
git checkout -- Cargo.lock
git pull
cargo build --release

# Install (old v1 binary may shadow in PATH)
sudo cp ~/deepdive/target/release/deepdive /usr/local/bin/
# Or use the binary directly without installing
~/deepdive/target/release/deepdive version
```

### Usage examples

```bash
# Scan a local repo (default: text output, exit 2 only if verdict is UNSAFE/BLOCK)
deepdive scan ./repo

# Deep scan with sandbox + JSON output
# (sandbox runs "true" by default unless --sandbox-cmd is given)
deepdive audit ./repo --deep --sandbox --sandbox-cmd "npm install && npm test" \
  --format json --out report.json

# Compare to a previous run (regression mode: exit 2 on new high/critical)
deepdive scan ./repo --baseline report.json --regression

# Check rules / update offline cache / test selftest
deepdive rules list
deepdive cache update --offline   # refreshes URLhaus feed when online
# (cache update tries the feed by default; --offline skips fetching)
```

## Status / what v2 added

v1.2 = static + YARA + Sigma + SBOM + lockfile checks.

v2.0 = sandbox with structured telemetry, network capture, Windows process/registry/memory
dumping, disassembly heuristics, Java/WASM/Android/.NET analyzers, baseline/regression mode,
Intel feed matching, and firmware carving.

Still open (from the plan): Windows AppContainer / restricted-token confinement, ETW syscall
tracing, Linux native backend validated as default, anti-analysis multi-run, ONNX ML signal,
plugin system, fuzz targets. See `~/.opencode/plan/deepdive-plan.md` §17.13.

## License

MIT OR Apache-2.0
