# vyre-libs publish gate

Pre-conditions every vyre-* crate must meet before being published
to crates.io. CI runs `scripts/check_publish_gate.sh <crate>` per
crate; nonzero exit blocks publish.

## Per-crate contract

1. **`SPEC.md`** at the crate root describing every public type +
   function. The Stage-2 release rules and the per-primitive contract
   (`skills/SKILL_BUILD_DATAFLOW_PRIMITIVE.md`) reference primitives
   by name; the SPEC is the source of truth those references resolve
   against.
2. **Every `pub fn` carries `///` doc comments** with `# Examples` +
   `# Errors` sections per Rust API guidelines. CI gate:
   `cargo doc --no-deps -p <crate>` exits 0 with no
   `missing_docs` warnings (already deny-warned for vyre-libs).
3. **`cargo test -p <crate> --all-features` green.** No `#[ignore]`
   tests in production paths. Test-only ignores live in `*-tests`
   sibling crates with explicit gate documentation.
4. **`scripts/check_primitive_contract.sh`** passes against every
   file under `vyre-libs/src/{security, dataflow}` and
   `vyre-primitives/src/{bitset, graph}`. Per-primitive rules:
     - module doc comment
     - `pub(crate) const OP_ID`
     - `pub fn cpu_ref`
     - ≥4 unit tests
     - ≤600 LOC
     - no `Program::new` (use `Program::wrapped`)
     - no `_ => panic|todo|unimplemented` catch-alls
5. **`cargo publish --dry-run -p <crate>`** exits 0. CI runs this
   for every changed crate per PR.
6. **CHANGELOG.md** has an entry for the new version with a
   `### Added` / `### Changed` / `### Removed` breakdown.
7. **No `[patch.crates-io]` entries** at the workspace root for the
   crate being published — every dep must come from crates.io or
   from a sibling workspace member with a published version pin.

## Per-version stability contract

vyre-libs follows semver. The wire format (`vyre-spec`) is FROZEN
at every published version and CHECKED by the conform suite —
adding a `BinOp` variant or a `Node` variant is a breaking change
that requires a major bump.

## Crates currently in publish scope

| Crate | Current pin | Publish target | Status |
| --- | --- | --- | --- |
| `vyre-spec` | 0.6.0 | crates.io | green (frozen wire) |
| `vyre-foundation` | 0.6.0 | crates.io | green |
| `vyre-primitives` | 0.6.0 | crates.io | gap: 3 new bitset ops need OpEntry registration |
| `vyre-libs` | 0.6.0 | crates.io | gap: `taint_kill` + `flows_to_to_sink` + `flows_to_with_sanitizer` need publish docs |
| `vyre-driver-wgpu` | 0.6.0 | crates.io | gap: `BinOp::WrappingAdd` upstream-spec drift |
| `surgec` | unpublished | crates.io | gap: Stage-1 CAP-1..14 incomplete |

## How to publish a crate

1. Run `bash scripts/check_publish_gate.sh <crate>`. Fix every
   reported defect.
2. Bump version in `Cargo.toml` per semver.
3. Update `CHANGELOG.md`.
4. `cargo publish --dry-run -p <crate>`.
5. PR for review. Merge.
6. `cargo publish -p <crate>` from main.
