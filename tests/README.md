# keyhog integration and end-to-end tests

This directory holds **repo-level** integration tests — Docker image scans,
install-script scenarios, CLI entrypoint smoke tests, and the cross-crate
file-gate matrix. Per-crate unit, contract, property, and adversarial tests
live under each crate's own `tests/` tree.

## Layout

| Path | What it tests |
|------|---------------|
| `tests/docker/` | Scanning inside glibc/musl Docker images; build-and-run scenarios. |
| `tests/install/` | OS-addressable install scenarios: Linux/macOS wrappers, Windows notes, and shared fixtures. |
| `tests/integration/` | CLI entrypoint smoke tests (`keyhog --help`, `--version`, etc.). |
| `tests/FILE_GATE_MATRIX.toml` | Per-source-file coverage matrix tracked by the file-gate CI job. |
| `tests/docs/` | Docs claim checks (CLI help ↔ README, etc.). |

## Most common commands

```bash
# Full workspace test suite
cargo test --workspace

# One crate
cargo test -p keyhog-core
cargo test -p keyhog-scanner
cargo test -p keyhog-cli

# Detector contract suite (recall / precision / evasion per detector)
cargo test -p keyhog-scanner --test contracts_runner

# Core invariant suite (spec validation, embedded detector parsing, etc.)
cargo test -p keyhog-core --test all_tests

# Run the same binary the release uses
cargo run --release -p keyhog -- scan .
```

## Test naming conventions inside crates

- `tests/unit/` — targeted unit tests for a single module.
- `tests/gap/` — regression tests that close a specific gap or ticket.
- `tests/property/` — proptest / fuzz-style invariant checks.
- `tests/contracts/` — per-detector data-driven contracts (`crates/scanner/tests/contracts/`).
- `tests/e2e/` / `tests/e2e_binary.rs` — full CLI-driven end-to-end tests.

See `docs/EXECUTION_PLAN.md` for the full testing model: data + multipliers + gates.
