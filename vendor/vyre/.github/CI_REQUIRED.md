# Required CI Jobs for Branch Protection

All jobs listed below are **required** to pass before a PR can merge into `main`.
This list is enforced by branch protection rules (see `scripts/apply-branch-protection.sh`).

## From `ci.yml` (run on every PR + push to main)
- `${os} / ${rust-toolchain}` matrix entries for:
  - `cargo fmt --check`
  - `cargo xtask abstraction-gate`
  - `cargo clippy --workspace -- -D warnings`
  - `cargo test --workspace`
  - `cargo doc --workspace`

## From `bench.yml` (run on PRs touching benchmarked crates)
- `criterion-regression`

## From `architectural-invariants.yml` (run on every PR)
- `architectural-invariants`
- `law-a-closed-enums`
- `law-b-string-wgsl`
- `law-b-shader-assets`
- `law-c-capability-negotiation`
- `law-d-unsafe-justifications`
- `dialect-coverage`
- `trait-freeze`
- `registry-consistency`
- `no-raw-unwrap`
- `no-hot-path-inventory`
- `no-opspec-tokens`
- `error-codes-cataloged`
- `consistency-contracts`
- `base-monument`
- `abstraction-gate`

## From `gpu-parity.yml` (run on self-hosted GPU runner)
- `Probe real GPU adapter`
- `WGPU backend contracts`
- `Composition parity on real GPU`
- `Determinism stress on real GPU`
- `Mandatory GPU enforcement`

## From `reproducible-build.yml` (nightly schedule)
- `reproducible` — nightly gate; not blocking on individual PRs but tracked in cycle reports.

## Scheduled or Manual Deep Gates
- `fuzz.yml` — full fuzz lane once active fuzz targets exist.
- `mutation-testing.yml` — weekly zero-survivor gate once restored from `workflows-paused`.
