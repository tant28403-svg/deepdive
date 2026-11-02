# deepdive

Scan repos and files **before** you run or clone them.

This tool checks code for secrets, malware patterns, bad dependencies, and suspicious binaries — then gives you a simple verdict: `SAFE`, `REVIEW`, `UNSAFE`, or `BLOCK`.

---

## Quick start

```bash
# Build
cargo build --release

# Basic scan of a folder
./target/release/deepdive scan ./my-repo

# Deep scan + dependencies + sandbox
./target/release/deepdive audit ./my-repo --deep --sandbox

# Save a JSON report
./target/release/deepdive scan ./my-repo --format json --out report.json
```

---

## What it checks

- **Files** — magic bytes, hidden payloads, strings, embedded binaries
- **Code** — secrets, suspicious patterns, deobfuscation hints
- **Dependencies** — bad package names, lockfile issues, known vulnerable versions
- **Git history** — changes that hide malicious code (with `--deep`)
- **Sandbox** — optional isolation that runs your repo and reports what it does (network, registry, files)

---

## Commands

| Command | What it does |
|---------|-------------|
| `deepdive scan .` | Quick static check of the current folder |
| `deepdive audit ./repo` | Deep scan + optional sandbox |
| `deepdive fetch <url>` | Download a repo/URL and scan before using |

---

## Common flags

| Flag | Meaning |
|------|---------|
| `--deep` | Include git history and dependency audit |
| `--sandbox` | Run in isolation (Docker or native) |
| `--sandbox-cmd "..."` | The command to run inside the sandbox |
| `--format text\|json\|sarif` | How to show results (default: text) |
| `--out file` | Write report to file instead of screen |
| `--offline` | Skip live network lookups |
| `--rules file` | Use your own rules file |
| `--fail-on high` | Exit with error if a high-severity finding appears |
| `--baseline prev.json --regression` | Compare to an old report; fail if new bad things appear |

---

## Sandbox quick info

If you use `--sandbox`, the tool picks the best isolation available:
- **Docker** if installed
- **Native** isolation otherwise (Linux namespaces / Windows process limits)

Before trusting native isolation, test it:

```bash
deepdive sandbox selftest --backend native --policy strict
```

Use `--sandbox-policy strict` for the tightest isolation, `network-capture` to log connections, or `permissive` for fewer restrictions.

---

## Install

```bash
git clone https://github.com/tant28403-svg/deepdive
cd deepdive
cargo build --release --features disasm,java,wasm   # full analyzers
sudo install -m 755 target/release/deepdive /usr/local/bin/
```

If the command is not found after install:

```bash
ls ~/deepdive/target/release/deepdive
sudo cp ~/deepdive/target/release/deepdive /usr/local/bin/
```

---

## Simple examples

```bash
# Scan a repo quickly
deepdive scan ./repo

# Deep scan with sandbox and JSON output
deepdive audit ./repo --deep --sandbox --sandbox-cmd "npm install && npm test" --format json --out report.json

# Check if anything new and bad appeared vs last run
deepdive scan ./repo --baseline report.json --regression

# List rules / update offline cache / test sandbox
deepdive rules list
deepdive cache update --offline
deepdive sandbox selftest --backend native --policy strict
```

---

## What you get back

A report with:
- **Verdict** — `SAFE` / `REVIEW` / `UNSAFE` / `BLOCK`
- **Score** — 0 to 100 (lower is better)
- **Findings** — what was detected, how severe, and where
- **Sandbox** — if used, what the code did while running (files changed, network calls, registry changes)

---

## Learn more

- Full flag docs: run `deepdive --help`
- Status / v2 features: see `src/` and project docs
- License: MIT OR Apache-2.0
