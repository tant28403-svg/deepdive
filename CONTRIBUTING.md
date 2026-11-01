# Contributing

## Building

```bash
cargo build
cargo test
cargo fmt --check
cargo clippy -- -D warnings
```

## Pull requests

- Keep PRs focused and small.
- Add tests for new detection rules.
- Update the plan in `~/.opencode/plan/deepdive-plan.md` if scope changes.

## Commit messages

`stage N: <short description>` or conventional commits (`feat:`, `fix:`, `docs:`).