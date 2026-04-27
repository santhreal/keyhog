# Appendix G — Examples index

Every worked example in the book, cross-referenced by
topic, category, and chapter. Useful when you are looking
for an example of a specific pattern and do not remember
where it appeared.

---

## Examples by test category

### Primitive op tests

- `test_add_identity_zero_zero_spec_table` —
  [worked-example/02-first-test.md](../worked-example/02-first-test.md).
  The canonical first test for BinOp::Add.
- `test_add_right_identity_dead_beef_plus_zero` —
  [worked-example/03-building-out.md](../worked-example/03-building-out.md).
- `test_add_u32_max_plus_one_wraps_to_zero` —
  [worked-example/03-building-out.md](../worked-example/03-building-out.md).
- `test_add_commutative_dead_beef_cafe_babe` —
  [worked-example/03-building-out.md](../worked-example/03-building-out.md).
  Uses the algebraic law oracle.
- `test_add_associative_triple` —
  [worked-example/03-building-out.md](../worked-example/03-building-out.md).
  Uses composition with multiple ops.
- `test_add_composition_with_overflow_matches_reference` —
  [worked-example/05-mutation-gate.md](../worked-example/05-mutation-gate.md).
  Added during mutation gate iteration.

### Validation tests

- `test_v001_rejects_duplicate_buffer_name` —
  [categories/validation.md](../categories/validation.md).
  Canonical must-reject example.
- `test_v001_accepts_distinct_buffer_names` —
  [categories/validation.md](../categories/validation.md).
  The must-accept complement.
- `test_v010_rejects_barrier_under_if_branch` —
  [writing/naming.md](../writing/naming.md).
  Example of rule family grouping.

### Lowering tests

- `test_lowering_of_binop_add` —
  [categories/lowering.md](../categories/lowering.md).
  Variant coverage test.
- `test_buffer_access_has_bounds_check` —
  [categories/lowering.md](../categories/lowering.md).
  Structural property test.
- `test_shl_has_shift_mask` —
  [categories/lowering.md](../categories/lowering.md).
  Safety property test.
- `every_expr_variant_is_tested` —
  [categories/lowering.md](../categories/lowering.md).
  Exhaustiveness meta-test pattern.

### Wire format tests

- `test_roundtrip_canonical_add_program` —
  [categories/wire_format.md](../categories/wire_format.md).
  Round-trip identity example.
- `test_decode_add` —
  [categories/wire_format.md](../categories/wire_format.md).
  Decoder test for a specific opcode.
- `test_encode_add` —
  [categories/wire_format.md](../categories/wire_format.md).
  Encoder test for a specific IR shape.

### Adversarial tests

- `test_deeply_nested_program_does_not_panic` —
  [categories/adversarial.md](../categories/adversarial.md).
  Resource bomb example.
- `test_ir_with_undeclared_buffer_ref_does_not_panic` —
  [categories/adversarial.md](../categories/adversarial.md).
  Malformed IR example.

### Property tests

- `wire_format_roundtrip_is_identity` —
  [categories/property.md](../categories/property.md).
  Canonical proptest example.
- `validated_programs_lower_safely` —
  [categories/validation.md](../categories/validation.md).
  Invariant I5 proptest.

### Backend tests

- `test_add_backend_equiv_reference_interp` —
  [categories/backend.md](../categories/backend.md).
  Reference interpreter oracle example.
- `test_add_cross_backend_agreement` —
  [categories/backend.md](../categories/backend.md).
  Skip-rule example.
- `test_reference_interp_agrees_with_cpu_refs` —
  [categories/backend.md](../categories/backend.md).
  I8 verification test.

### Regression tests

- `regression_shl_by_32_produces_zero` —
  [categories/regression.md](../categories/regression.md).
  Canonical regression example with full header.

### Adversarial / determinism

- `test_atomic_add_determinism_256_threads` —
  [advanced/concurrency-and-ordering.md](../advanced/concurrency-and-ordering.md).
  Determinism stress test.
- `test_two_thread_increment_every_interleaving` —
  [advanced/concurrency-and-ordering.md](../advanced/concurrency-and-ordering.md).
  Exhaustive interleaving test.

### Floating-point

- `test_add_f32_one_plus_two_strict` —
  [advanced/floating-point.md](../advanced/floating-point.md).
  Strict track example.
- `test_sine_approximate_within_four_ulp` —
  [advanced/floating-point.md](../advanced/floating-point.md).
  Approximate track example.
- `test_add_f32_round_to_even_exact_tie` —
  [advanced/floating-point.md](../advanced/floating-point.md).
  Round-to-even edge case.

---

## Examples by anti-pattern

### Tautology test examples

- Direct tautology —
  [anti-patterns/tautology.md](../anti-patterns/tautology.md).
- Indirect (via helper) —
  [anti-patterns/tautology.md](../anti-patterns/tautology.md).
- Subtle (via shared reference) —
  [anti-patterns/tautology.md](../anti-patterns/tautology.md).

### Kitchen sink examples

- Multi-property single function —
  [anti-patterns/kitchen-sink.md](../anti-patterns/kitchen-sink.md).

### Doesn't-crash examples

- Unasserted result —
  [anti-patterns/doesnt-crash.md](../anti-patterns/doesnt-crash.md).
- Existence-only assertion —
  [anti-patterns/doesnt-crash.md](../anti-patterns/doesnt-crash.md).

### Hidden helper examples

- Index-based test cases —
  [anti-patterns/hidden-helpers.md](../anti-patterns/hidden-helpers.md).
- Builder pattern tests —
  [anti-patterns/hidden-helpers.md](../anti-patterns/hidden-helpers.md).

### Seedless proptest examples

- Missing `ProptestConfig` —
  [anti-patterns/seedless-proptest.md](../anti-patterns/seedless-proptest.md).
- Missing regression corpus —
  [anti-patterns/seedless-proptest.md](../anti-patterns/seedless-proptest.md).

---

## Examples by test smell

- Error message assertion —
  [anti-patterns/test-smells.md](../anti-patterns/test-smells.md).
- Unwrap without context —
  [anti-patterns/test-smells.md](../anti-patterns/test-smells.md).
- Magic numbers —
  [anti-patterns/test-smells.md](../anti-patterns/test-smells.md).
- Ordering dependency —
  [anti-patterns/test-smells.md](../anti-patterns/test-smells.md).
- Unexplained `#[ignore]` —
  [anti-patterns/test-smells.md](../anti-patterns/test-smells.md).
- Direct struct construction —
  [anti-patterns/test-smells.md](../anti-patterns/test-smells.md).
- `let _ = ...` for side effects —
  [anti-patterns/test-smells.md](../anti-patterns/test-smells.md).
- Overlong setup —
  [anti-patterns/test-smells.md](../anti-patterns/test-smells.md).

---

## Examples by helper / template

- `build_single_binop` — primitive op factory.
  Appears throughout the book.
- `build_program` builder — composed Program construction.
  [worked-example/03-building-out.md](../worked-example/03-building-out.md).
- `run_on_default_backend` — dispatch wrapper.
  [categories/support.md](../categories/support.md).
- `run_on_every_backend` — cross-backend dispatch.
  [categories/support.md](../categories/support.md).
- `assert_shader_compiles` — WGSL validation helper.
  [categories/lowering.md](../categories/lowering.md).
- `spec_table_lookup` — oracle helper.
  [categories/support.md](../categories/support.md).
- `assert_law` — law oracle helper.
  [categories/support.md](../categories/support.md).
- `assert_agrees_with_reference` — reference interpreter
  helper. [categories/support.md](../categories/support.md).
- `ulp_distance` — float tolerance helper.
  [advanced/floating-point.md](../advanced/floating-point.md).

---

## Examples by oracle kind

### Algebraic law oracle

- Commutativity (`test_add_commutative_dead_beef_cafe_babe`)
- Associativity (`test_add_associative_triple`)
- Identity (`test_add_identity_zero_law_witness_12345678`)

### Spec table oracle

- Most primitive op tests in `worked-example/03-building-out.md`.

### Reference interpreter oracle

- `test_add_cross_backend_reference_equivalence`
- Composed Program tests in
  `worked-example/03-building-out.md`.

### Property oracle

- Proptest examples in `categories/property.md`.
- Fuzz target examples in
  `advanced/differential-fuzzing.md`.

---

## Examples by mutation class

Examples demonstrating tests that kill specific mutation
classes.

### Arithmetic mutations

- `test_add_commutative_*` kills
  `ArithOpSwap { Add, Sub }` (not fully, but contributes).
- `test_add_u32_max_plus_one_*` kills overflow mutations.

### Lowering mutations

- `test_buffer_access_has_bounds_check` kills
  `LowerRemoveBoundsCheck`.
- `test_shl_has_shift_mask` kills `LowerRemoveShiftMask`.

### Law mutations

- Every law test contributes to killing
  `LawFalselyClaim` mutations.

---

## How to use this index

- When you need an example of a specific pattern, find it
  here by category, anti-pattern, or oracle.
- When you are writing a test, find the closest example
  and adapt it.
- When you are learning the book, browse the index to find
  examples you have not seen yet.

The examples are all in-book. Running them as real Rust
code requires the full vyre workspace, but they are
written to be understandable in isolation.
