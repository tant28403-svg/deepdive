# deepdive

> **A security scanner that analyzes code, dependencies, binaries, and git history *before* you run or clone them.**  
> Detects malware, secrets, supply-chain attacks, and suspicious behavior -- then gives you a clear verdict: **SAFE**, **REVIEW**, **UNSAFE**, or **BLOCK**.

## What is deepdive?

`deepdive` is a command-line tool for developers and security teams to **reverse-engineer and safety-check repositories, files, and binaries** before executing them. It combines static analysis, dependency auditing, binary inspection, and optional sandbox execution into a single workflow.

**Use cases:**
- **Pre-commit / CI gate**: Block malicious code before it lands
- **Dependency review**: Find typosquatting, vulnerable versions, lockfile drift
- **Malware triage**: Analyze suspicious binaries, scripts, archives, firmware
- **Supply-chain security**: Verify third-party code before adding as dependency
- **Incident response**: Quickly assess what a compromised artifact does

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Commands](#commands)
- [Flags Reference](#flags-reference)
- [Output Formats](#output-formats)
- [What Gets Scanned](#what-gets-scanned)
- [Understanding the Verdict](#understanding-the-verdict)
- [Sandbox Isolation](#sandbox-isolation)
- [Baseline & Regression Testing](#baseline--regression-testing)
- [Custom Rules](#custom-rules)
- [Offline Mode & Caching](#offline-mode--caching)
- [Project Structure](#project-structure)
- [Configuration Files](#configuration-files)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Quick Start

```bash
# 1. Build the project
git clone https://github.com/tant28403-svg/deepdive
cd deepdive
cargo build --release

# 2. Quick scan of a local folder
./target/release/deepdive scan ./my-project

# 3. Deep audit with sandbox + JSON report
./target/release/deepdive audit ./my-project --deep --sandbox --format json --out report.json

# 4. Scan a remote repo before cloning
./target/release/deepdive fetch https://github.com/user/repo --deep --format json
```

---

## Installation

### From Source (Recommended)

```bash
# Standard build
cargo build --release

# Full feature build (all analyzers: disassembly, Java, .NET, WASM, YARA)
cargo build --release --features disasm,java,dotnet,wasm,yara

# Install to PATH
sudo install -m 755 target/release/deepdive /usr/local/bin/
```

### Requirements

- **Rust 1.93+** (install via [rustup.rs](https://rustup.rs))
- **Git** (for `fetch` and `audit` commands)
- **Docker** (optional, for sandbox backend)
- **Linux**: `bubblewrap` or `firejail` for native sandbox (optional)

---

## Commands

| Command | Description |
|---------|-------------|
| `deepdive scan <path>` | Scan a local file or directory |
| `deepdive audit <target>` | Deep scan: local path OR remote URL + git history + optional sandbox |
| `deepdive fetch <url>` | Clone a remote repository safely, then scan it |
| `deepdive rules <action>` | Manage detection rules (list, test) |
| `deepdive cache <action>` | Manage offline cache (update, clear) |
| `deepdive sandbox <action>` | Sandbox diagnostics (selftest) |
| `deepdive completions <shell>` | Generate shell completions (bash, zsh, fish, powershell, elvish) |
| `deepdive --version` | Print version |

---

### `scan` -- Local Static Analysis

```bash
# Scan a directory
deepdive scan ./my-project

# Scan a single file
deepdive scan ./suspicious-script.sh

# With options
deepdive scan ./my-project --deep --offline --format json --out results.json
```

### `audit` -- Deep Scan (Local or Remote)

```bash
# Local path with git history
deepdive audit ./my-project --deep --sandbox

# Remote URL (clones to temp, scans, cleans up)
deepdive audit https://github.com/user/repo --deep --sandbox

# Keep the cloned repo after scanning
deepdive audit https://github.com/user/repo --keep ./cloned-repo

# Custom sandbox command
deepdive audit ./my-project --sandbox --sandbox-cmd "npm install && npm test"
```

### `fetch` -- Clone & Scan Remote Repos

```bash
# Clone and scan (deletes temp clone after)
deepdive fetch https://github.com/user/repo

# Clone specific branch
deepdive fetch https://github.com/user/repo --branch develop

# Scan only a subdirectory
deepdive fetch https://github.com/user/repo --path ./subdir

# Keep the repo locally
deepdive fetch https://github.com/user/repo --keep ./my-copy

# Include submodules
deepdive fetch https://github.com/user/repo --submodules
```

---

## Flags Reference

### Scan / Audit / Fetch Common Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `text` | Output format: `text`, `json`, `sarif` |
| `--out` | `-o` | stdout | Write report to file instead of stdout |
| `--min-severity` | | `info` | Minimum severity to display (filters output only, not verdict) |
| `--offline` | | `false` | Skip all network calls (use cached data) |
| `--deep` | | `false` | Enable git history + dependency vulnerability audit |
| `--sandbox` | | `false` | Run target in isolation after static scan |
| `--sandbox-cmd` | | `true` (Unix) / `cmd /c exit 0` (Windows) | Command to run inside sandbox |
| `--sandbox-backend` | | `auto` | Sandbox backend: `auto`, `docker`, `native`, `none` |
| `--sandbox-policy` | | `strict` | Sandbox policy: `strict`, `network-capture`, `permissive`, or TOML file |
| `--intel` | | `false` | Match extracted URLs/hosts against cached threat intel |
| `--rules` | | - | Extra rules file/directory (TOML, Sigma YAML, YARA) |
| `--fail-on` | | - | Exit code 2 if any finding ≥ severity (e.g., `high`) |
| `--baseline` | | - | Path to previous JSON report for comparison |
| `--regression` | | `false` | With `--baseline`: exit 2 if new High/Critical findings |
| `--sbom` | | - | Generate SBOM: `cyclonedx` or `spdx` (instead of scan) |
| `--max-size` | | `100` | Skip files larger than N MB |
| `--threads` | | CPU count | Parallelism limit |
| `--no-color` | | `false` | Disable colored output |

### `fetch` Specific Flags

| Flag | Description |
|------|-------------|
| `--branch` | Git branch to checkout |
| `--path` | Subdirectory to scan (relative to repo root) |
| `--keep` | Local path to keep the cloned repo |
| `--submodules` | Clone submodules (disabled by default) |

---

## Output Formats

### Text (Default)

Human-readable summary with verdict, score, and findings:

```
deepdive scan: ./my-project
files scanned: 234
  source           180
  config            32
  binary            12
  archive           10

VERDICT: REVIEW  (risk score 23/100)

[HIGH] dangerous.exec-eval - ./src/utils.js
  line 42: Use of eval()
  > eval(userInput);

[MEDIUM] secrets.generic-api-key - ./config/prod.json
  line 15: Generic API key pattern
  > "api_key": "sk_live_abc123..."

Summary: critical=0, high=1, medium=3, low=5, info=2
```

### JSON (`--format json`)

Machine-readable, includes full schema:

```json
{
  "schema_version": "2.0",
  "files_scanned": 234,
  "risk_score": 23,
  "verdict": "REVIEW",
  "suppressed": 0,
  "findings": [
    {
      "id": "dangerous.exec-eval-./src/utils.js-42",
      "severity": "High",
      "confidence": 0.7,
      "rule": "dangerous.exec-eval",
      "category": "dangerous-api",
      "location": { "path": "./src/utils.js", "line": 42, "column": null },
      "message": "Use of eval()",
      "snippet": "eval(userInput);",
      "tags": []
    }
  ],
  "sandbox": null,
  "baseline": null
}
```

### SARIF (`--format sarif`)

Compatible with GitHub Code Scanning, VS Code, and other tools:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "deepdive",
        "version": "2.0.0",
        "informationUri": "https://github.com/tant28403-svg/deepdive",
        "rules": [
          { "id": "dangerous.exec-eval", "name": "dangerous.exec-eval", ... }
        ]
      }
    },
    "results": [
      { "ruleId": "dangerous.exec-eval", "level": "error", ... }
    ]
  }]
}
```

### SBOM (`--sbom cyclonedx|spdx`)

Software Bill of Materials instead of scan report:

```bash
deepdive scan ./my-project --sbom cyclonedx --out sbom.json
deepdive scan Cargo.lock --sbom spdx --out sbom.spdx.json
```

---

## What Gets Scanned

### 1. File-Level Analysis
- **Magic bytes & file type detection** -- Identifies PE, ELF, Mach-O, ZIP, TAR, GZIP, WASM, APK, DEX, etc.
- **Embedded payloads** -- Carves hidden executables, scripts, and firmware images from polyglots
- **String extraction** -- URLs, IPs, PowerShell commands, registry paths, base64 blobs
- **Entropy analysis** -- Detects packed/encrypted sections

### 2. Source Code Analysis
- **Secrets detection** -- API keys, tokens, passwords, private keys, JWTs, cloud credentials
- **Dangerous APIs** -- `eval()`, `exec()`, `child_process`, `ProcessBuilder`, `Runtime.exec`, `os.system`, `subprocess`, PowerShell IEX/encoded commands, download cradles
- **Obfuscation patterns** -- Base64 decode chains, `fromCharCode`, `atob`, dynamic `compile()`, string concatenation tricks
- **AST-based taint tracking** -- JavaScript/TypeScript (via tree-sitter) and Python data-flow from sources to sinks
- **Sigma & YARA rules** -- Custom detection rules in Sigma (YAML) or YARA format
- **Polyglot detection** -- Files valid as multiple formats simultaneously

### 3. Binary Analysis (PE/ELF/Mach-O)
- **Dangerous imports** -- `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `URLDownloadToFile`, etc.
- **Authenticode signature verification** -- Checks for valid code signing
- **Embedded PE detection** -- Finds dropped payloads in overlays/sections
- **Version metadata masquerading** -- Detects binaries pretending to be system files
- **Overlay data** -- Appended payloads after last section

### 4. Dependency Audit
- **Lockfile parsing** -- `Cargo.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `go.mod`, `pom.xml`, `build.gradle`, `composer.lock`
- **Known vulnerabilities** -- Queries OSV.dev (cached offline)
- **Typosquatting detection** -- Edit-distance matching against top packages (with allowlist)
- **Dependency confusion** -- Internal package names matching public registries
- **Lockfile integrity** -- Hash mismatches, manifest drift

### 5. Git History (with `--deep`)
- **Secret scanning in commits** -- Finds secrets added then "removed"
- **Dangerous API in diffs** -- Suspicious code added in history
- **Commit metadata analysis** -- Anomalous authors, timestamps, messages

### 6. Platform-Specific
- **Windows** -- LOLBins (certutil, bitsadmin, regsvr32, rundll32, mshta), scheduled tasks, registry persistence, ADS streams
- **Android** -- DEX analysis, manifest permissions, native libraries
- **Java/.NET/WASM** -- Bytecode/IL/WASM module analysis (feature-gated)
- **Firmware** -- SquashFS, UBI, CramFS, JFFS2 extraction and scanning

---

## Understanding the Verdict

| Verdict | Score Range | Meaning | Exit Code |
|---------|-------------|---------|-----------|
| **SAFE** | 0–10 | No significant findings | 0 |
| **REVIEW** | 11–40 | Low/medium findings, manual review recommended | 1 |
| **UNSAFE** | 41–70 | High-severity findings or multiple medium | 2 |
| **BLOCK** | 71–100 | Critical findings or severe malicious indicators | 2 |

**Score calculation**: Weighted by severity × confidence
- Critical: 25 pts
- High: 15 pts
- Medium: 8 pts
- Low: 3 pts
- Info: 1 pt

**Override**: Any `Critical` finding → `UNSAFE` (minimum)

### `--fail-on` Flag

```bash
# Exit 2 if any High or Critical finding
deepdive scan ./repo --fail-on high

# Exit 2 if any Medium+
deepdive scan ./repo --fail-on medium
```

---

## Sandbox Isolation

Run the target in an isolated environment and observe its behavior.

### Backends

| Backend | Platform | Isolation Level |
|---------|----------|-----------------|
| `docker` | Linux/macOS/Windows | Container (strongest) |
| `native` (Linux) | Linux | Namespaces + seccomp + cgroups |
| `native` (Windows) | Windows | Job Objects + process limits |
| `auto` | Any | Prefers Docker, falls back to native |

### Policies

| Policy | Network | Filesystem | Use Case |
|--------|---------|------------|----------|
| `strict` | Blocked | Read-only (except workspace) | Maximum isolation |
| `network-capture` | Captured (MITM proxy) | Read-only | Network behavior analysis |
| `permissive` | Allowed | Read-write | Compatibility testing |

### Usage

```bash
# Quick sandbox test (no-op command)
deepdive scan ./repo --sandbox

# Run actual build/test in sandbox
deepdive audit ./repo --sandbox --sandbox-cmd "npm install && npm test"

# Capture network traffic
deepdive scan ./repo --sandbox --sandbox-policy network-capture

# Use Docker backend explicitly
deepdive scan ./repo --sandbox --sandbox-backend docker

# Test if sandbox works on this machine
deepdive sandbox selftest --backend native --policy strict
```

### Sandbox Report Includes

- Process tree (spawned children)
- Files created/modified/deleted
- Network connections (IP, port, protocol)
- Registry changes (Windows)
- Memory dumps of suspicious processes
- Syscall trace (Linux native)
- Stdout/stderr capture
- Exit code & timeout status

---

## Baseline & Regression Testing

Compare scans over time to catch new issues.

```bash
# 1. Create baseline
deepdive scan ./repo --format json --out baseline.json

# 2. Later: compare against baseline
deepdive scan ./repo --baseline baseline.json --format json --out current.json

# 3. Regression gate (CI-friendly)
deepdive scan ./repo --baseline baseline.json --regression
# Exit code 2 if new High/Critical findings appear
```

**Baseline report shows:**
- `new` findings (not in baseline)
- `resolved` findings (fixed since baseline)
- Diff summary in text/JSON output

---

## Custom Rules

Add your own detection rules without recompiling.

### Rule Formats

| Format | Extension | Use For |
|--------|-----------|---------|
| TOML | `.toml` | Regex-based patterns with metadata |
| Sigma | `.yml`/`.yaml` | Structured log/event rules |
| YARA | `.yar`/`.yara` | Binary/memory pattern matching |

### TOML Rule Example

```toml
# my-rules.toml
[[rules]]
name = "internal-api-key"
description = "Detects our internal API key format"
severity = "Critical"
confidence = 0.9
category = "secrets"
patterns = [
  "sk_internal_[a-zA-Z0-9]{32}",
  "INTERNAL_API_KEY\\s*=\\s*[\"'][^\"']+[\"']"
]
tags = ["internal", "api-key"]
```

### Using Custom Rules

```bash
# Single file
deepdive scan ./repo --rules ./my-rules.toml

# Directory of rules
deepdive scan ./repo --rules ./rules-dir/

# Also checks ~/.config/deepdive/rules/ automatically
```

### Manage Rules

```bash
# List built-in + user rules
deepdive rules list

# Validate a rule file
deepdive rules test ./my-rules.toml
```

---

## Offline Mode & Caching

### `--offline` Flag

Completely disables network access:
- No OSV vulnerability queries
- No threat intel feed updates
- No GitHub API calls (for `fetch`/`audit` URLs)
- Uses only local cache

```bash
deepdive scan ./repo --offline --deep
```

### Cache Management

```bash
# Update cache (downloads threat intel, populates OSV cache)
deepdive cache update

# Update cache without network (shows what's cached)
deepdive cache update --offline

# Clear all cached data
deepdive cache clear
```

**Cache location**: `~/.cache/deepdive/` (Linux/macOS) or `%LOCALAPPDATA%\deepdive\cache\` (Windows)

---

## Project Structure

```
deepdive/
├── Cargo.toml                 # Project manifest, features, dependencies
├── src/
│   ├── main.rs                # Entry point, CLI dispatch
│   ├── cli.rs                 # Command definitions, argument parsing
│   ├── engine.rs              # Core scan pipeline orchestration
│   ├── risk.rs                # Scoring & verdict logic
│   ├── types.rs               # Shared types (Finding, Severity, Verdict, SandboxReport)
│   ├── config.rs              # Global & project config (.deepdive.toml)
│   │
│   ├── acquisition/           # Repository acquisition
│   │   ├── mod.rs
│   │   ├── git.rs             # Safe git clone (shallow, no hooks)
│   │   └── url.rs             # URL parsing (HTTPS, SSH, GitHub shorthand)
│   │
│   ├── analysis/              # Static analysis engines
│   │   ├── mod.rs             # Analysis dispatch
│   │   ├── walker.rs          # File walking (.gitignore-aware, skips .git/)
│   │   ├── file_type.rs       # Magic-byte + extension detection
│   │   ├── scan.rs            # Text file scanning entry point
│   │   ├── secrets.rs         # Secret/credential detection
│   │   ├── source.rs          # Dangerous API patterns (140+ built-in rules)
│   │   ├── obfuscation.rs     # Deobfuscation heuristics
│   │   ├── deobfuscate.rs     # Decoders (base64, rotN, xor, char codes)
│   │   ├── rules.rs           # TOML custom rule engine
│   │   ├── sigma.rs           # Sigma rule parser/evaluator
│   │   ├── yara.rs            # YARA compilation + scanning (feature-gated)
│   │   ├── ast.rs             # AST-based taint analysis (JS/TS, Python)
│   │   ├── binary.rs          # PE/ELF/Mach-O analysis (goblin)
│   │   ├── archive.rs         # ZIP/TAR/GZIP extraction + scanning
│   │   ├── document.rs        # Office/PDF analysis
│   │   ├── firmware.rs        # Filesystem image carving
│   │   ├── disasm.rs          # x86 disassembly + CFG (feature: disasm)
│   │   ├── android.rs         # APK/DEX analysis
│   │   ├── dotnet.rs          # .NET assembly analysis (feature: dotnet)
│   │   ├── java.rs            # Java class/JAR analysis (feature: java)
│   │   ├── wasm.rs            # WebAssembly module analysis (feature: wasm)
│   │   ├── git_history.rs     # `git log -p` secret/dangerous-API scan
│   │   ├── baseline.rs        # Baseline comparison logic
│   │   ├── intel.rs           # Cached threat intel (URL/host matching)
│   │   ├── windows_extras.rs  # Windows-specific (LOLBins, tasks, ADS)
│   │   ├── symlinks.rs        # Symlink traversal detection
│   │   ├── polyglot.rs        # Multi-format file detection
│   │   ├── config.rs          # Config file analysis
│   │   ├── build.rs           # Build script analysis
│   │   └── deps/              # Dependency analysis
│   │       ├── mod.rs         # Dependency collection dispatch
│   │       ├── parsers.rs     # Lockfile parsers (8+ formats)
│   │       ├── osv.rs         # OSV vulnerability queries + typosquatting
│   │       └── integrity.rs   # Lockfile integrity + confusion checks
│   │
│   ├── reporting/             # Output formatters
│   │   ├── mod.rs
│   │   ├── sarif.rs           # SARIF 2.1.0 output
│   │   └── sbom.rs            # CycloneDX + SPDX SBOM generation
│   │
│   └── sandbox/               # Dynamic analysis (isolation)
│       ├── mod.rs             # Backend selection, behavioral findings
│       ├── policy.rs          # Policy/Backend enums, parsing
│       ├── process.rs         # Cross-platform process execution
│       ├── snapshot.rs        # Filesystem snapshot + diff
│       ├── selftest.rs        # Escape probe tests
│       ├── docker.rs          # Docker backend
│       ├── windows_native.rs  # Windows Job Objects backend
│       ├── linux_native.rs    # Linux bwrap/firejail backend
│       ├── linux/             # Linux native internals
│       │   ├── namespaces.rs
│       │   ├── seccomp.rs
│       │   └── cgroups.rs
│       ├── network/           # Network capture (MITM proxy)
│       │   ├── proxy.rs
│       │   ├── dns.rs
│       │   └── beacon.rs
│       ├── telemetry.rs       # Process/tree/network event types
│       ├── registry.rs        # Windows registry snapshots
│       ├── proctree.rs        # Process tree snapshots
│       ├── memory.rs          # Memory dumping
│       └── error.rs           # Typed sandbox errors
│
├── tests/
│   └── integration_cli.rs     # End-to-end CLI tests
│
├── .github/workflows/
│   ├── ci.yml                 # fmt + clippy + test (3 OS) + feature matrices
│   └── release.yml            # Cross-platform release builds
│
├── install.sh                 # Quick install script
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

---

## Configuration Files

### Global Config (`~/.config/deepdive/config.toml`)

```toml
# Global defaults (can be overridden by CLI flags)
min_severity = "medium"
offline = false
rules = ["/path/to/custom/rules/"]
```

### Project Config (`.deepdive.toml` in repo root)

```toml
# Per-repo allowlist & rule overrides
[allowlist]
# Suppress specific findings by rule ID
rules = ["dangerous.fs-rmtree", "secrets.generic-api-key"]

# Suppress findings in specific paths
paths = ["tests/", "examples/", "vendor/"]

# Suppress by tag
tags = ["test-data"]

[rule_overrides]
# Change severity of a built-in rule
"dangerous.child-process" = "Low"

# Disable a rule entirely
"binary.strings-urls" = "Off"
```

---

## Examples

### Daily Developer Workflow

```bash
# Before running npm install in a new project
deepdive scan ./new-project --offline

# Before committing
deepdive scan . --fail-on high

# CI gate
deepdive scan . --format sarif --out results.sarif
# Upload results.sarif to GitHub Code Scanning
```

### Security Review of Dependencies

```bash
# Deep dependency audit
deepdive scan ./repo --deep --offline

# Generate SBOM for compliance
deepdive scan Cargo.lock --sbom cyclonedx --out sbom.cdx.json

# Check for known vulnerabilities
deepdive scan ./repo --deep  # (online, queries OSV)
```

### Malware Triage

```bash
# Suspicious file
deepdive scan ./suspicious.exe --format json

# Archive with potential payload
deepdive scan ./unknown.zip --deep

# Firmware image
deepdive scan ./router-firmware.bin --deep
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  deepdive:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run deepdive
        run: |
          cargo install deepdive --locked --features disasm,java,wasm,yara
          deepdive scan . --format sarif --out deepdive.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: deepdive.sarif
```

### Regression Testing in CI

```bash
# Store baseline as artifact
deepdive scan . --format json --out baseline.json

# On subsequent runs
deepdive scan . --baseline baseline.json --regression --format json
# Fails (exit 2) if new High/Critical findings introduced
```

---

## Troubleshooting

### "Command not found" after install
```bash
# Verify binary exists
ls -la target/release/deepdive

# Add to PATH manually
export PATH="$PATH:/path/to/deepdive/target/release"
```

### Running old binary after rebuild (verdict doesn't change)

If you rebuilt `deepdive` but still see old behavior (e.g., `BLOCK` verdict when it should be `UNSAFE`):

```bash
# 1. Check which binary is actually running
which deepdive
# If it points to /usr/local/bin/deepdive (old installed), that's the problem

# 2. Run the freshly built binary directly
cd deepdive
./target/release/deepdive --version
./target/release/deepdive fetch https://github.com/tant28403-svg/adobo --deep

# 3. Reinstall the new binary
sudo cp target/release/deepdive /usr/local/bin/deepdive

# Or add build dir to PATH permanently
export PATH="$HOME/deepdive/target/release:$PATH"
# Add to ~/.bashrc or ~/.zshrc
```

**Why this happens:** `cargo build` puts the binary in `target/release/`, but your shell may find an older copy in `/usr/local/bin/` or `~/.cargo/bin/` first. Always run `which deepdive` to check.

### Sandbox fails on Windows
```bash
# Test native backend
deepdive sandbox selftest --backend native --policy strict

# If it fails, install Docker Desktop and use:
deepdive scan . --sandbox --sandbox-backend docker
```

### "No cached feed" warning with `--intel`
```bash
# Run once online to populate cache
deepdive cache update

# Then use offline
deepdive scan . --intel --offline
```

### Too many false positives
```bash
# Create .deepdive.toml in repo root
cat > .deepdive.toml <<'EOF'
[allowlist]
rules = ["dangerous.fs-rmtree"]
paths = ["tests/", "fixtures/"]
EOF
```

### Scan takes too long
```bash
# Skip large files
deepdive scan . --max-size 10

# Limit parallelism
deepdive scan . --threads 4

# Offline mode (no network calls)
deepdive scan . --offline
```

### YARA rules won't compile
```bash
# Rebuild with YARA feature
cargo build --release --features yara

# Test your rules
deepdive rules test ./my-rules.yara
```

---

## Performance Tips

| Scenario | Recommendation |
|----------|----------------|
| Large repos (10k+ files) | Use `--max-size 50 --threads 8` |
| CI pipelines | Use `--offline` with pre-warmed cache |
| Binary-heavy projects | Enable `--features disasm` for deeper PE/ELF analysis |
| Java/Android/WASM targets | Enable respective features (`java`, `android`, `wasm`) |
| Recurring scans | Use `--baseline` to focus on changes |

---

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `git-backend-gix` | Pure-Rust git backend (optional) | ❌ |
| `git-backend-git2` | libgit2 backend | ❌ |
| `yara` | YARA rule support | ❌ |
| `native-sandbox` | Linux namespaces/seccomp/cgroups | ❌ |
| `disasm` | x86 disassembly (iced-x86) | ❌ |
| `android` | APK/DEX analysis | ❌ |
| `dotnet` | .NET assembly analysis | ❌ |
| `java` | Java bytecode analysis | ❌ |
| `wasm` | WebAssembly analysis | ❌ |

Build with features:
```bash
cargo build --release --features yara,disasm,java,wasm
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and PR process.

### Running Tests
```bash
cargo test                    # Unit + integration
cargo test --features yara    # With YARA
cargo test --features android,disasm,dotnet,java,wasm  # All features
```

### Code Quality
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security policy.

- No telemetry, no phone-home
- All network access is explicit (`--intel`, OSV queries, git clone)
- Sandbox isolates untrusted code execution
- Supply-chain: minimal dependencies, `cargo audit` in CI

---

## License

Dual-licensed under **MIT OR Apache-2.0**.

```
Copyright (c) 2024-present tant28403-svg
```

---

## Links

- **Repository**: https://github.com/tant28403-svg/deepdive
- **Issues**: https://github.com/tant28403-svg/deepdive/issues
- **Releases**: https://github.com/tant28403-svg/deepdive/releases
- **Documentation**: See `deepdive --help` and this README