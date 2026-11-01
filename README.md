# deepdive

Reverse-engineer and safety-check repositories and files **before** you run or clone them.

deepdive is a cross-platform (Windows + Linux) CLI tool that combines static analysis, dependency auditing, binary triage, and opt-in sandboxed dynamic execution to produce a risk score and verdict (`SAFE` / `REVIEW` / `UNSAFE` / `BLOCK`).

## Status

v1.0.0 is released. Post-1.0 work is landing incrementally:

- `v1.1` — recursive archives and symlink escapes, expanded file types, Windows artifacts (ADS/reparse points, `.lnk`, MSI, scheduled tasks, OLE macros), deeper binary triage.
- `v1.2` — YARA and Sigma rules, SBOM export, lockfile integrity, dependency confusion, taint-aware AST.
- Deferred to `v2` — syscall tracing, network capture, memory dumps, anti-analysis multi-run, disassembly/CFG, .NET/Java/Android/WASM, ML/ONNX, firmware.

See the plan in `~/.opencode/plan/deepdive-plan.md`.

## Rules

Built-in rules are listed with `deepdive rules list`. Custom rules can be dropped in the
user rules directory (TOML, Sigma YAML, or YARA) or passed per scan with `--rules`:

```bash
deepdive scan ./repo --rules ./rules/custom.toml
deepdive scan ./repo --rules ./rules/suspicious.yml   # Sigma subset
deepdive rules test ./rules/custom.yar
```

YARA support is an optional build feature (it pulls in a WebAssembly runtime). Build it with:

```bash
cargo build --release --features yara   # requires Rust 1.95+
```

Sigma support is a static subset: detection selectors are evaluated against file lines,
including `and`/`or`/`not`, `N of`, `all of`, wildcards, and common modifiers
(`contains`, `startswith`, `endswith`, `re`, `all`). It is intended for dropped
command-line/script artifacts, not event-log correlation.

## Install

### From source (clone from GitHub)

```bash
git clone https://github.com/tant28403-svg/deepdive
cd deepdive
cargo build --release
sudo install -m 755 target/release/deepdive /usr/local/bin/
```

### One-liner from GitHub

```bash
cargo install --git https://github.com/tant28403-svg/deepdive --locked
```

### Prebuilt (no Rust needed)

```bash
curl -fsSL https://raw.githubusercontent.com/tant28403-svg/deepdive/main/install.sh | sh
```

### Docker

```bash
docker run --rm -v "$PWD:/work" ghcr.io/tant28403-svg/deepdive scan /work
```

## Usage

```bash
deepdive scan ./suspicious-repo
deepdive scan ./payload.exe --format json --out report.json
deepdive fetch https://github.com/user/repo --keep ./repo
deepdive audit https://github.com/user/repo --sandbox --fail-on high
```

## License

MIT OR Apache-2.0