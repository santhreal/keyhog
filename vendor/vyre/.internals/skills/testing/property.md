# property.md — invariant testing with proptest

## What goes here

Tests that prove **a property holds for every input in some
strategy**, not just the hand-picked examples in a unit test. The
property tier is where contracts live: pre-conditions, post-conditions,
invariants that must hold across the API.

## Checklist — every property suite covers

### Algebraic laws

- [ ] Identity: `op(x, e) == x` for every value `x` and the op's
  identity element `e`
- [ ] Associativity / commutativity where the op claims them
- [ ] Inverses: `op(x, inv(x)) == e` when the op has inverses
- [ ] Absorption, distributivity, De Morgan — every law the op
  claims in its metadata

### Round-trip

- [ ] `decode(encode(x)) == x` — every codec, every representable
  value
- [ ] `parse(format(x)) == x` — every text serializer
- [ ] `deserialize(serialize(x)) == x` — every serde impl

### Monotonicity

- [ ] Adding a buffer never reduces `min_input_bytes`
- [ ] Increasing `workgroup_size` never reduces `output_word_count`
- [ ] Property checks that are `Fn(InputSize) -> OutputSize` are
  monotonic in the documented direction

### Idempotence

- [ ] Optimizer passes: `pass(pass(p)) == pass(p)` (fixpoint)
- [ ] Validation: `validate(p) == validate(validate_then_clone(p))`
- [ ] Cache: `insert(k, v); insert(k, v)` produces the same state
  as a single insert

### Equivalence classes

- [ ] Two representations that should be equal ARE equal
  (canonical-form check)
- [ ] Two representations that should NOT be equal are not equal
  (anti-aliasing — critical for cache keys)

### Bounds

- [ ] Output size ≤ declared max for every input
- [ ] Allocator never returns more than requested
- [ ] `count()` returns the same number of elements that the
  iterator yielded

### Parity (vyre-specific)

- [ ] Every GPU lowering produces bytes identical to the CPU
  reference for every KAT + proptest-generated input
- [ ] Every optimizer pass preserves semantics: `eval(p) ==
  eval(pass(p))` for every valid program

## Strategy discipline

- **Shrink aggressively.** A good strategy shrinks failures to the
  smallest input that reproduces. Use `proptest::collection::vec(strategy, 0..=N)`
  with small N, bump N only when coverage demands it.
- **No `prop_assume!` to hide bugs.** `prop_assume!(x != y)` is
  sometimes necessary for well-defined operations (division by
  zero); `prop_assume!(!is_the_bug_input(x))` is evasion.
- **Every test sets a seed.** `ProptestConfig { cases: 1024, seed:
  Some(42), ..default() }`. Seeds are for regression replay, not
  flakiness avoidance. If a test flakes without a seed, the test is
  wrong.
- **Regressions are checked in.** `<crate>/tests/<test>.proptest-regressions`
  files track every failing case the CI or local run has ever seen.

## Template

```rust
//! Property tests for `<crate>`.
//!
//! See `../../.internals/skills/testing/property.md` for the category contract
//! and `tests/SKILL.md` for this crate's specific invariants.

use proptest::prelude::*;
use <crate>::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1024,
        ..ProptestConfig::default()
    })]

    #[test]
    fn round_trip(p in program_strategy()) {
        let bytes = p.to_wire().expect("valid programs serialize");
        let decoded = Program::from_wire(&bytes).expect("emitted bytes decode");
        prop_assert_eq!(decoded, p);
    }

    #[test]
    fn optimizer_is_idempotent(p in program_strategy()) {
        let once = optimize(p.clone());
        let twice = optimize(once.clone());
        prop_assert_eq!(once, twice);
    }

    #[test]
    fn validate_accepts_optimized(p in program_strategy()) {
        let optimized = optimize(p);
        prop_assert!(validate(&optimized).is_ok());
    }
}

fn program_strategy() -> impl Strategy<Value = Program> {
    (
        prop::collection::vec(buffer_strategy(), 0..=8),
        workgroup_strategy(),
        prop::collection::vec(node_strategy(), 0..=32),
    ).prop_map(|(bs, wg, entry)| Program::wrapped(bs, wg, entry))
}
```

## Anti-patterns

- **Testing the implementation, not the contract.** If the test
  breaks when the implementation refactors but the contract is
  unchanged, the test is wrong. Rewrite against the contract.
- **Giant strategies.** A strategy that generates 1 KB programs in
  the first case is unshrinkable. Start small, grow.
- **Catching every error variant.** If the contract says "must
  return `InvalidProgram`", the test checks for that variant
  specifically — not `is_err()`.
- **Using `seed: None` on CI.** Flaky tests on CI means the seed
  is random — ban random seeds on the main branch.

## Proptest + adversarial — where lines differ

- `adversarial.rs` = hand-crafted hostile inputs + boundary cases.
  One test per invariant, each targeted. Named so reviewers see the
  attack surface at a glance.
- `property.rs` = proptest strategies over general-shape inputs.
  One test per *property*, validated over thousands of cases.

Good crates have both. Great crates have every adversarial test
mirrored by a property test that generalizes the same class.
