# Naming

## Why naming matters more than it seems

When there are fifteen tests in a file, naming is a convenience.
Contributors can scan the file visually and find what they need.
When there are fifteen hundred, naming is infrastructure.
Contributors rely on `cargo test <substring>` to filter, on
directory listings to navigate, on failure output to understand
what broke. A naming scheme that works for fifteen tests can
fail silently for fifteen hundred, and vyre's test suite is
expected to grow past fifteen thousand.

The naming convention in this chapter is not about aesthetics.
It is about making the suite navigable at scale, making failures
diagnosable from the test runner output, and making `cargo test`
filtering predictable. Consistency across the whole suite is the
point; any consistent convention would work, but vyre has picked
one and this chapter describes it.

## The convention

Every test in vyre follows the pattern:

```
test_<subject>_<property>[_<oracle>]
```

- `test_` is the standard Rust prefix for test functions. Always
  present.
- `<subject>` is what the test exercises: the op, the validator
  rule, the subsystem, the feature.
- `<property>` is the specific claim being verified.
- `<oracle>` is optional and, when present, names the oracle
  that provided the expected value.

The parts are joined with underscores. The whole name is
snake_case. Names are descriptive, not cute. Names are long
enough to be unambiguous and short enough to type.

## Examples by category

### Primitive op tests

```
test_add_identity_zero_zero_spec_table
test_add_right_identity_dead_beef_plus_zero
test_add_overflow_u32_max_plus_one_wraps_to_zero
test_add_commutative_dead_beef_cafe_babe
test_add_associative_triple
test_add_bit_pattern_alternation
test_xor_self_inverse_produces_zero
test_shl_by_thirty_two_masks_to_zero
test_mul_zero_is_absorbing
```

The subject is always the op name. The property is the specific
claim. The oracle is named when it is not obvious: `spec_table`
for specific-input tests, implied law names for law tests.

### Validation tests

```
test_v001_rejects_duplicate_buffer_name
test_v001_accepts_distinct_buffer_names
test_v010_rejects_barrier_under_if_branch
test_v010_rejects_barrier_under_while_loop
test_v010_accepts_barrier_in_uniform_block
test_v017_rejects_program_with_ten_thousand_and_one_nodes
test_v017_accepts_program_with_ten_thousand_nodes
```

The subject is always `v<NNN>` where NNN is the rule number.
The property is always "rejects <scenario>" or "accepts
<scenario>" — no exceptions. This makes the separability
meta-test's enumeration straightforward and the mental model
uniform across the category.

### Lowering tests

```
test_lowering_of_binop_add
test_lowering_of_binop_sub
test_lowering_of_atomic_add
test_lowering_of_workgroup_buffer
test_every_expr_variant_is_tested
test_buffer_access_has_bounds_check
test_shl_has_shift_mask
```

The subject is the construct being lowered. The property is the
aspect of the lowering being verified. Meta-tests use descriptive
names that hint at their meta nature (`every_expr_variant_is_tested`).

### Adversarial tests

```
test_deeply_nested_program_does_not_panic
test_truncated_wire_format_returns_error
test_oom_during_validation_returns_error
test_out_of_range_buffer_index_does_not_ub
test_fuzz_corpus_entry_a3f2e1b_does_not_panic
```

Adversarial tests almost always contain the word `does_not_panic`
or similar, which makes the intent obvious at a glance. Fuzz
corpus replay tests include an identifier from the corpus file.

### Property tests

```
fn wire_format_roundtrip_is_identity(program in arb_program()) { ... }
fn validation_soundness_for_random_programs(program in arb_program()) { ... }
fn determinism_across_runs(program in arb_program(), runs in 2..100usize) { ... }
```

Property test names are statements of the invariant. They omit
the `test_` prefix because they are inside `proptest!` blocks
and the macro adds its own infrastructure. The name reads as
the invariant being asserted.

### Regression tests

```
#[test]
fn regression_shl_by_thirty_two_produces_zero() { ... }

#[test]
fn regression_wire_decode_empty_loop_does_not_panic() { ... }
```

Regression test functions are named `regression_<short_description>`
and live in a file named `YYYY-MM-DD-<short_description>.rs`. The
file name carries the date; the function name carries the short
description. Together they make the regression searchable by
date or by symptom.

### Backend tests

```
test_add_cross_backend_reference_equivalence
test_canonical_programs_are_deterministic_across_runs
test_reference_interp_agrees_with_cpu_refs
test_every_registered_backend_is_exercised
```

Backend test names mention the word `backend`, `cross_backend`,
or `reference` to distinguish them from other categories that
happen to exercise similar infrastructure.

### Benchmarks

```
bench_dispatch_single_add
bench_validate_one_thousand_node_program
bench_wire_encode_canonical_program
```

Benchmarks use the prefix `bench_` instead of `test_` because
criterion looks for that prefix. The `bench_<subject>_<what>`
pattern mirrors the test convention.

## What names must do

A test name must:

- **Uniquely identify the test within its file.** Two tests with
  the same name cannot coexist.
- **Identify the subject.** A reader who sees the name knows
  what code is being exercised.
- **Identify the property.** A reader who sees the name knows
  what claim is being verified.
- **Be matchable by `cargo test` substring filters.** A reader
  who wants to run "all Add tests" types `cargo test test_add_`
  and the runner filters to the right set.
- **Be searchable in logs.** When a test fails in CI, the name
  appears in the log, and a reader can grep for the name to
  find the test file.

A test name must not:

- **Be ambiguous.** `test_add` does not say what about Add is
  being tested. Always include a property.
- **Duplicate information from the filename.** `test_add_something`
  in `add.rs` does not need to repeat `add` in every test name
  (but the convention says to include it anyway for
  consistency).
- **Encode implementation details.** `test_add_uses_helper_x`
  names a helper, not a property. Implementation details change;
  properties do not.
- **Be cute.** `test_add_works` is cute. `test_add_produces_expected_sum_on_specific_inputs`
  is not cute but it is clear.

## Length

Test names in vyre are long. `test_add_u32_max_plus_u32_max_wraps_to_max_minus_one`
is not unusual. The length is the price of clarity, and vyre
pays it because the alternative is test names that do not say
what they test.

The Rust test runner handles long names without truncation. The
`cargo test <substring>` filter handles any substring, so the
longer name is not harder to invoke. Editors and IDEs offer
autocompletion for long names. The only cost is horizontal
space in source files, which is negligible.

A name longer than 80 characters is worth splitting into a
shorter name plus a doc comment that expands on it. Most names
fit in 60 characters, which is under any reasonable line-length
limit.

## Consistency within a file

Tests in the same file should use consistent naming across
related tests. If three tests verify variations on the same
property, their names should differ in the varying part and
agree on the rest:

```rust
// GOOD — consistent
fn test_add_identity_zero_plus_zero() { ... }
fn test_add_identity_dead_beef_plus_zero() { ... }
fn test_add_identity_zero_plus_cafe_babe() { ... }

// BAD — inconsistent
fn test_add_zero_is_identity() { ... }
fn test_add_identity_right() { ... }
fn test_zero_left_of_add_preserves_value() { ... }
```

The good version makes it clear all three tests are identity
tests with different operands. The bad version makes the reader
do extra work to see the relationship.

## Naming rules for specific situations

Some situations call for specific naming conventions beyond the
general pattern.

### Tests using hex literals

When the inputs are hex literals, the name should include a
short description of the pattern rather than the full hex
value. `test_add_dead_beef_plus_cafe_babe` is preferred to
`test_add_0xDEADBEEF_plus_0xCAFEBABE` because underscores
in hex constants make the name harder to read.

### Tests covering boundaries

Boundary tests include the boundary name in the test name:
`test_add_u32_max_plus_one_wraps_to_zero`, `test_shl_by_thirty_two_masks_to_zero`.
The boundary is what makes the test interesting, so the name
highlights it.

### Tests exercising a specific mutation class

When a test was specifically written to kill a mutation class
discovered by the mutation gate, the name should hint at the
mutation: `test_add_distinguishes_from_sub_on_overflow`. The
name makes the intent explicit so future contributors know why
the test exists.

### Meta-tests

Meta-tests that iterate over enum variants or enumerate the
suite for coverage use the prefix `test_every_` or
`test_no_<undesired_property>`:

```
test_every_expr_variant_is_tested
test_every_v_rule_has_a_must_reject_test
test_no_test_uses_tautological_oracle
```

## Renaming

If a test is named wrong, rename it. Renames are cheap in Rust:
the compiler finds every reference, and there should be very
few (tests are usually only referenced by their own file). A
rename PR has a clear scope and is easy to review.

What is not acceptable is leaving a misleading name "because it
is already there." Misleading names compound: future contributors
follow the pattern of the existing names and introduce new tests
that are also misleading. Fix names when you notice them.

## Summary

Tests in vyre follow `test_<subject>_<property>[_<oracle>]`.
Names are descriptive, consistent within files, long enough to
be unambiguous, and mechanically filterable. Naming is
infrastructure, not aesthetics. The convention serves
navigability at the scale vyre expects to reach.

Next: [Support utilities in writing](support-utilities.md) —
how to build helpers that clarify rather than obscure.
