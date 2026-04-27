# Release Checklist

Run this checklist before every crates.io publish. Every box must be ticked. No exceptions.

## Build

- [ ] `cargo check --workspace` — 0 errors across every crate
- [ ] `cargo test --workspace` — all tests pass (note failures in any of the 4 publishable crates: vyre, vyre-conform, vyre-spec, vyre-build-scan)
- [ ] `cargo clippy --workspace -- -D warnings` (accept warnings for now, but note count)
- [ ] `cargo fmt --check` — formatting clean
- [ ] `scripts/publish-dryrun.sh` — every publishable crate passes `cargo publish --dry-run`

## Invariants

- [ ] `scripts/check_trait_freeze.sh` — all 6 frozen traits at their canonical paths
- [ ] CI job `dag-no-cycles` — no circular module dependencies
- [ ] CI job `cat-b-tripwires` — no forbidden patterns in production source
- [ ] `certify()` returns `Ok` for the reference backend on all registered ops (or a known-good subset for alpha)
- [ ] `CpuOp` trait defined in `vyre-core/src/ops/cpu_op.rs`; every registered op has a working path (Cat A via interpreter, Cat C explicit)
- [ ] No hand-written `fn wgsl()` oracles remain in `vyre-conform/src/specs/` — oracle uses real `core::lower::wgsl` output
- [ ] No duplicated op metadata: `VYRE_OP_METADATA`, `AddSpecSource`, `spec_layer_source` all removed from `vyre-conform/src/specs/`
- [ ] Every primitive has a `rules/kat/primitive/<op>.toml` with ≥3 KAT vectors + ≥1 adversarial
- [ ] `rules/SCHEMA.md#kat` matches every shipped KAT file

## Benchmarks (ship-blocking for 0.4.0+)

- [ ] `benches/primitives_showcase.rs` has a row for every op in `core::ops::registry`
- [ ] `cargo bench -p vyre --bench primitives_showcase` produces real numbers on this machine (RTX 5090)
- [ ] `benches/RESULTS.md` regenerated and committed with the run
- [ ] `benches/RESULTS.json` regenerated and committed
- [ ] README top-of-file `## Benchmarks` section updated with the latest top-of-table
- [ ] `vyre-core/docs/benchmarks.md` rendered in the book with the full table
- [ ] Any op that panics or produces wrong GPU output = a finding in `audits/bench_findings.md`; fixed before ship (no skipped rows)

## Documentation

- [ ] `README.md` at monorepo root is accurate
- [ ] `CHANGELOG.md` has entries for this version
- [ ] `CONTRIBUTING.md` reflects current flows
- [ ] `ARCHITECTURE.md` reflects current architecture
- [ ] Each publishable crate has `README.md` (becomes crates.io landing page)
- [ ] Each publishable crate has `LICENSE-MIT` and `LICENSE-APACHE`
- [ ] The vyre book (`vyre-core/docs/`) is up to date

## Versioning

- [ ] `Cargo.toml` versions bumped per SemVer (`vyre`, `vyre-conform`, `vyre-spec`, `vyre-build-scan`)
- [ ] `git tag v{version}` created
- [ ] GitHub release draft with `CHANGELOG` excerpt

## Publish order (lower layer first)

1. `cargo publish -p vyre-spec`
2. `cargo publish -p vyre-build-scan`
3. `cargo publish -p vyre`
4. `cargo publish -p vyre-conform`

(Each publish: wait ~30s for crates.io to index before the next dependent publish.)

Tick each step before proceeding to the next:

- [ ] Step 1: `vyre-spec` published and indexed
- [ ] Step 2: `vyre-build-scan` published and indexed
- [ ] Step 3: `vyre` published and indexed
- [ ] Step 4: `vyre-conform` published and indexed

## Post-publish

- [ ] `cargo install vyre-conform && vyre-conform --help` works from a fresh env
- [ ] docs.rs has rendered the new version within 30 minutes
- [ ] GitHub release is published (not draft)
- [ ] Notification posted: Telegram @SanthCEObot, team Discord, etc.
- [ ] Bookkeeping: update `STATUS.md` or similar if present

## Rollback plan

If post-publish a critical bug is found:

1. Yank the version: `cargo yank -p <crate> --version X.Y.Z`
2. Ship a patch release `X.Y.(Z+1)` with the fix
3. Document the yank reason in `CHANGELOG.md`
4. Notify users via GitHub release note

## Rules

- Use checkbox format (GitHub-rendered).
- No emojis.
- Numbered sub-steps where order matters.
- Do not skip sections.
