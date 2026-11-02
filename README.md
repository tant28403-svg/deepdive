# deepdive

Reverse-engineer and safety-check repositories and files **before** you run or clone them.

deepdive is a cross-platform (Windows + Linux) CLI tool that combines static analysis, dependency auditing, binary triage, and opt-in sandboxed dynamic execution to produce a risk score and verdict (`SAFE` / `REVIEW` / `UNSAFE` / `BLOCK`).

## Status

v2.0.0 is released. Work landed incrementally:

- `v1.1` — recursive archives and symlink escapes, expanded file types, Windows artifacts (ADS/reparse points, `.lnk`, MSI, scheduled tasks, OLE macros), deeper binary triage.
- `v1.2` — YARA and Sigma rules, SBOM export, lockfile integrity, dependency confusion, taint-aware AST.
- `v2.0` — sandbox foundation (typed policy/backends, structured telemetry in the JSON report,
  enforced timeouts, `deepdive sandbox selftest`), network capture (HTTP/CONNECT proxy, fake DNS,
  beacon/DGA analysis), Windows process monitor with registry diffs and executable memory dumps,
  disassembly heuristics (`disasm`), Java/WASM/Android/.NET analyzers, baseline/regression mode,
  cached URLhaus intel matching, and firmware image carving.
- Still open — Windows AppContainer/restricted-token confinement and ETW syscall telemetry,
  validating the `native-sandbox` Linux backend as the default, anti-analysis multi-run,
  the ONNX classifier, and the plugin system. Tracked in the plan's status appendix.

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

## Disassembly

Build with `cargo build --release --features disasm` to decode PE/ELF executable sections
with iced-x86 and flag indirect control flow (dynamic API resolution, obfuscation) and
anti-analysis instructions (`disasm.anti-analysis`, `disasm.indirect-control-flow`).

## Managed runtimes

Optional analyzers, off by default:

- `--features java` — scans `.class` constant pools and every `.class` inside JAR/WAR/APK
  archives for process execution, JNDI, deserialization, and remote class-loading references.
- `--features wasm` — flags WASI imports that grant filesystem or network access and
  dangerous `env` host functions.
- `--features android` — scans `classes*.dex` string tables in APKs for process execution,
  dynamic code loading, SMS, reflection, and package-install APIs.
- `--features dotnet` — reads the CLI `#Strings` heap from managed assemblies and flags
  runtime assembly loading, P/Invoke, process start, downloads, registry access, and
  obfuscator markers.

## Regression mode and threat intel

```bash
deepdive scan ./repo --format json --out baseline.json
deepdive scan ./repo --baseline baseline.json --regression
deepdive cache update          # refresh the cached URLhaus feed
deepdive scan ./repo --intel   # match URLs/hosts in text files against the feed
```

Baseline comparison fingerprints findings by rule, path, and line, reports new and resolved
findings, and exits 2 on new high/critical findings in `--regression` mode. Intel matching
emits `intel.url-match` for URLs, hostnames, and raw IPs found in the cached feed.

## Dependency checks

deepdive reads npm, pnpm, Yarn, Cargo, pip, Go, and Bundler metadata. In addition to
OSV advisories and typosquatting, it flags:

- lockfile entries resolved over plain HTTP, unpinned git references, missing or
  malformed integrity hashes, and outdated lockfile versions;
- private-scope npm packages that resolve from the public registry, `--extra-index-url`
  in `requirements.txt`, and private registries configured without `always-auth`;
- manifest drift between `package.json`/`Pipfile`/`go.mod` and their lockfiles.

These checks are static and offline. Upstream hash verification against registry APIs is
planned for a later release.

## Taint analysis

For JavaScript, TypeScript, and Python, deepdive performs a lightweight taint pass over
the syntax tree. It marks common user-controlled sources (`process.argv`, `process.env`,
`req.query`, `location.search`, `sys.argv`, `os.environ`, `request.form`, `input()`, ...)
and reports when that data reaches a sink such as `eval`, `Function`, `child_process`,
`os.system`, `subprocess`, `pickle.loads`, `yaml.load`, or SQL `.execute`/`.query`.
Taint propagates through simple assignments. This is intentionally conservative, not a
full data-flow engine.

## Sandbox

Dynamic execution is opt-in and deepdive never invents a command:

```bash
deepdive scan ./repo --sandbox --sandbox-cmd "npm install && npm test"
deepdive scan ./repo --sandbox --sandbox-backend native --sandbox-policy strict
deepdive sandbox selftest --backend auto
```

Backends: `auto` (Docker when available, otherwise native), `native` (bubblewrap/firejail on
Linux, Job Objects on Windows), `docker`, `none`. The `network-capture` policy starts a local
HTTP/CONNECT proxy and fake DNS resolver, points the sandboxed process at them, and reports
per-host traffic plus `sandbox.network.*` findings (raw IPs, uncommon ports, DGA-style names,
DNS tunnelling, beaconing). A namespaces + seccomp + cgroup backend for
Linux lives behind the `native-sandbox` cargo feature; build with
`cargo build --features native-sandbox` once it has been validated on a Linux runner with
unprivileged user namespaces. Policies: `strict`, `network-capture`,
`permissive`, or a TOML file. The JSON report carries a `sandbox` object with the backend,
policy, file diffs, network indicators, and — as the native backends land — process, syscall,
registry, and memory-dump telemetry (`schema_version` 2.0).

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
deepdive scan ./repo --offline --sbom cyclonedx --out sbom.json
deepdive scan ./repo --offline --sbom spdx
deepdive fetch https://github.com/user/repo --keep ./repo
deepdive audit https://github.com/user/repo --sandbox --fail-on high
```

## License

MIT OR Apache-2.0