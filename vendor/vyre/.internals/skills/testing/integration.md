# integration.md — cross-crate + API-boundary testing

## What goes here

Tests that exercise the crate's **public API the way a downstream
consumer would**, and tests that verify cross-crate contracts when
this crate is part of a multi-crate pipeline.

## Checklist — every integration suite covers

### Public API from a consumer's perspective

- [ ] Every `pub fn` / `pub struct` / `pub trait` has a test that
  imports it through its documented path (not a crate-internal
  path) and exercises it end-to-end
- [ ] Doctests cover the canonical happy path; integration tests
  cover the tangle — chained calls, option combinations, error
  propagation through multiple layers
- [ ] `use <crate>::prelude::*;` (if the crate exports one) brings
  in exactly what the consumer needs — no reaching for non-prelude
  items

### Feature flags

- [ ] Every feature flag has a test gated on that feature that
  exercises the feature's surface
- [ ] Default-features and no-default-features builds are both
  tested (CI matrix)
- [ ] Feature combinations that are allowed to coexist: both-on
  test. Feature combinations that conflict: a compile-fail test
  via `trybuild`

### Cross-crate contracts

- [ ] When crate A declares a trait and crate B implements it, the
  integration test exercises B through A's generic API — proving
  the impl satisfies the trait's documented contract
- [ ] When crate A produces bytes that crate B consumes (e.g. wire
  format, OpDef registration), the integration test round-trips
  through both crates
- [ ] Version compatibility: when crate A exports a type with
  `#[non_exhaustive]` and crate B matches on it with a `_ =>`
  fallback, the integration test confirms the fallback path fires
  on a new variant

### Consumer dry-checks

- [ ] For workspace-member crates: every downstream consumer in the
  same repo builds against this crate (handled by
  `scripts/check_consumers.sh` at the workspace level)

### Workflow tests

- [ ] The README's "Quick start" snippet compiles and runs
- [ ] Every example in `examples/` compiles and runs, producing
  deterministic output (verified against a checked-in golden)
- [ ] The README's "How to add a <op>" / "How to register a
  <backend>" walkthrough produces a working result; the test
  follows the steps literally

## Template

```rust
//! Integration tests for `<crate>`.
//!
//! See `../../.internals/skills/testing/integration.md` for the category
//! contract and `tests/SKILL.md` for this crate's cross-crate
//! surface.
//!
//! These tests import the crate through its public path
//! (`use <crate>::*;`) — never through a `crate::` relative path.
//! This confirms the published surface is sufficient for a real
//! downstream consumer.

use <crate>::*;

#[test]
fn quick_start_from_readme() {
    // The exact sequence the README promises.
    let program = Program::builder()
        .buffer("input", DataType::U32, BufferAccess::ReadOnly)
        .buffer("output", DataType::U32, BufferAccess::ReadWrite)
        .workgroup_size([64, 1, 1])
        .build()
        .expect("README quick-start must succeed");
    assert_eq!(program.buffers().len(), 2);
    assert_eq!(program.workgroup_size(), [64, 1, 1]);
}

#[test]
fn cross_crate_wire_round_trip() {
    // vyre-foundation encodes, vyre-driver-wgpu decodes.
    use vyre_foundation::ir::Program;
    let program = sample_program();
    let bytes = program.to_wire().unwrap();
    // The driver decodes through the same type — no cross-crate
    // type shim should be necessary.
    let decoded = Program::from_wire(&bytes).unwrap();
    assert_eq!(decoded, program);
}
```

## Integration vs unit

- **Unit tests** (inline `#[cfg(test)]` modules in source files)
  test private behavior against internal invariants. They use
  `crate::`.
- **Integration tests** (files in `tests/`) test the public API
  exactly as a consumer sees it. They `use <crate>::...`.

The two tiers have different blast radius: a unit-test refactor is
free, an integration-test refactor means every consumer update.

## Anti-patterns

- **Using `pub(crate)` back doors in integration tests** to reach
  internals. Integration tests exercise only the published API.
- **Depending on shared mutable state** between tests in one file.
  Cargo runs tests in a thread pool — tests that depend on order
  or global state are broken by default.
- **Integration tests that silently skip when a dependency isn't
  available.** If the test requires a GPU, `cfg(target_os = "macos")`,
  or a network, gate it with a documented feature flag; don't
  auto-skip.
- **`Mock`-everything tests named "integration"**. An integration
  test exercises real cross-crate behavior. A unit test with mocks
  is still a unit test.
