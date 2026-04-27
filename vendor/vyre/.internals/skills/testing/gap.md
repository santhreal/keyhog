# gap.md — designed-to-fail tests

## What goes here

Tests that **assert what the crate SHOULD do** against what it
currently does. Gap tests document *engine gaps*. A passing gap test
is either (a) the gap closed — celebrate, migrate to `property.rs` —
or (b) the test is wrong.

## Core rule

A gap test file should have tests that fail today. When they start
passing, the engine improved; when they start failing harder, the
engine regressed. Either direction is a signal.

## Checklist — every gap suite covers

- [ ] Features the crate's README / spec claims but doesn't yet
  implement — each claim a failing test
- [ ] Performance targets the crate has stated — a `#[cfg(not(ci))]`
  bench test that panics when the measured time exceeds the goal
- [ ] Known precision / correctness gaps — e.g. floating-point ULP
  bounds that current lowering violates
- [ ] Missing error variants — every error case the API surface
  implies should be distinguishable via a matching test
- [ ] Composition gaps — two operations that should compose cleanly
  per the algebra but don't yet
- [ ] Backend coverage gaps — every op on every backend is covered
  by a parity test; gaps surface when a backend doesn't support an
  op yet

## How a gap test is written

```rust
//! Gap tests for `<crate>`.
//!
//! See `../../.internals/skills/testing/gap.md` for the category contract and
//! `tests/SKILL.md` for this crate's specific gap list.
//!
//! EVERY TEST IN THIS FILE IS EXPECTED TO FAIL against the current
//! implementation. A passing test here either means the engine
//! closed the gap (migrate the test to property.rs or
//! adversarial.rs and link the commit that closed it) or the test
//! is wrong (rewrite).

use <crate>::*;

/// Gap #1 (READNE.md §Roadmap) — the crate claims "streams of any
/// size" but the decoder caps at 16 MiB. Closing: lift the cap in
/// src/decode.rs or chunk the payload.
#[test]
#[should_panic(expected = "gap: 16 MiB cap")]
fn accepts_17_mib_program() {
    let program = generate_program(17 * 1024 * 1024);
    let bytes = program.to_wire().expect("encoder has no cap");
    // Current engine panics with the gap message. When the engine
    // lifts the cap, this assertion triggers the should_panic
    // failure and the reviewer migrates the test.
    let _ = Program::from_wire(&bytes).unwrap();
}

/// Gap #2 (ARCHITECTURE.md §Determinism) — the spec claims strict
/// IEEE 754 single-precision conformance. Current fma lowering
/// rounds differently than the CPU reference on denormals.
#[test]
fn fma_denormal_parity() {
    let a = f32::from_bits(0x00400000); // denormal
    let b = 1.0f32;
    let c = 0.0f32;
    let gpu = gpu_fma(a, b, c);
    let cpu = cpu_fma(a, b, c);
    // This assertion fails today. When the gap closes it passes —
    // migrate it into property.rs as a proptest over all denormals.
    assert_eq!(
        gpu.to_bits(),
        cpu.to_bits(),
        "gap: denormal fma parity not yet implemented"
    );
}
```

## Two gap idioms

### `#[should_panic]` — when current engine panics

Mark the test with `#[should_panic(expected = "...")]`. When the
engine stops panicking, the assertion fails and the reviewer gets
the signal.

### Plain `assert!` — when current engine returns a wrong-but-
graceful result

The assertion fails today because the engine returns the wrong
value. The test name carries `gap:` so reviewers can grep for
"currently failing on purpose".

## CI + gap tests

- Gap tests run in a **separate test binary** (`cargo test --test
  gap`) so the main test run stays green.
- CI runs gap tests and **reports passes** as findings (the gap
  closed!) and **reports failures** as expected state.
- `scripts/check_tests_can_fail.sh` is the gate that confirms at
  least some gap tests still fail. If every gap test passes, we
  either closed every gap (rename the file and link the commit)
  or stopped adding new gaps (LAW 9 — no evasion).

## Anti-patterns

- **`#[ignore]` on a gap test**. Ignoring a test is evasion.
  `#[should_panic]` or plain failing assertions — never `#[ignore]`.
- **Gap tests that pass silently**. A gap test must either fail or
  be migrated. "It's flaky" is a gap finding, not a reason.
- **Deleting a gap test** because the gap is "known". The whole
  point is a machine-checkable record of the gap. Delete only when
  the engine closes it, and replace with a property/adversarial
  test mirroring the closure.
- **Gap tests without a cited source**. Every gap test's doc-comment
  names the spec / README / issue that defines the gap. Otherwise
  it's just a failing test — noise.
