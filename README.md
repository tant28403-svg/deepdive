# deepdive

Reverse-engineer and safety-check repositories and files **before** you run or clone them.

deepdive is a cross-platform (Windows + Linux) CLI tool that combines static analysis, dependency auditing, binary triage, and opt-in sandboxed dynamic execution to produce a risk score and verdict (`SAFE` / `REVIEW` / `UNSAFE` / `BLOCK`).

## Status

Early development — Stage 1 (scaffold). See the plan in `~/.opencode/plan/deepdive-plan.md`.

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