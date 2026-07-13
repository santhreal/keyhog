# keyhog CI operability tests

This is a **standalone** Rust test crate (not part of the main workspace) that
verifies repository-wide CI contracts: workflow shape, spec-waiver hygiene,
release-matrix coverage, and dependency-pinning policy.

It is intentionally lightweight so it can run without compiling the full
keyhog crate graph.

## Run

```bash
cd tools/ci-operability
cargo test
```

## Layout

- `tests/gap/`: regression tests that close specific CI-operability gaps.
- `tests/gap/support/`: shared helpers (`repo_root`, `read_workflow`, `spec_waiver_active`, `STRICT_RUNNERS`).
- `spec_waivers/`: time-bounded waiver files referenced by the gap tests.

## Adding a waiver

If a gap test is temporarily waived, create a TOML file here with an
`expires = "YYYY-MM-DD"` field. The corresponding gap test will skip its
assertion while the waiver is active and fail closed once it expires.
