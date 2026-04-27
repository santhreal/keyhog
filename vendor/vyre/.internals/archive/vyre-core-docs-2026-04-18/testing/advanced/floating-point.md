# Floating-point

## The hardest semantics to preserve

Floating-point arithmetic is where vyre's determinism promise
is most stressed. Every GPU backend has license to optimize
float operations in ways that produce "close enough" results,
and "close enough" is not byte-identical. vyre's specification
forbids the optimizations that break determinism, but
enforcement requires careful testing because the optimizations
are subtle, the violations are rare, and the consequences are
invisible most of the time.

This chapter is about testing floating-point in vyre. It
covers the two conformance tracks (strict IEEE 754 and
approximate), the specific edge cases that matter (subnormals,
NaN, infinity, signed zeros, round-to-even), and the discipline
that prevents float semantics from drifting silently across
backends.

## The two tracks

vyre supports two tracks for floating-point:

### Strict IEEE 754 track

Every float operation produces the exact IEEE 754 result. No
fused multiply-add. No reordered reductions. No subnormal
flushing. No vendor math library substitutions. No approximate
reciprocals. The output of `f32::add(a, b)` on any conformant
backend is the exact IEEE 754 sum of `a` and `b`.

The strict track is slow (sometimes dramatically so) but
deterministic. vyre Programs that declare `FloatMode::Strict`
run in this track.

### Approximate track

Float operations produce results within a specified ULP
tolerance of the exact IEEE 754 result. The tolerance is
declared per operation and is typically 1-4 ULP for common
operations. The track is faster because it allows some of the
optimizations the strict track forbids, and the tolerance
bounds make the allowed inexactness predictable.

vyre Programs that declare `FloatMode::Approximate` run in
this track. Tests in this mode assert results within the
tolerance, not exact equality.

## Testing strict track

Strict track tests assert byte-identical float output across
every backend. The assertion is strict equality on the bit
representation, not approximate equality:

```rust
/// Float add of (1.0, 2.0) produces exactly 3.0 (strict IEEE 754).
/// Oracle: SpecRow from vyre-conform::spec::tables::add_f32.
#[test]
fn test_add_f32_one_plus_two_strict() {
    let program = build_single_fadd(1.0f32, 2.0f32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result.to_bits(), 3.0f32.to_bits(), "1.0 + 2.0 should be 3.0");
}
```

The comparison uses `to_bits()` to avoid any ambiguity about
what "equal" means for floats. `assert_eq!(result, 3.0)`
would pass even if `result` is `2.9999999` because of the
way float comparison works; `assert_eq!(result.to_bits(),
3.0f32.to_bits())` compares the bit patterns directly and is
exact.

The cross-backend strict test iterates backends and asserts
the same bit pattern:

```rust
#[test]
fn test_add_f32_cross_backend_strict() {
    let program = build_single_fadd(0.1f32, 0.2f32);

    let mut first_bits: Option<u32> = None;
    for backend in vyre::runtime::registered_backends() {
        let result = backend.run(&program, &[]).expect("dispatch");
        let bits = f32::from_ne_bytes(result).to_bits();
        match first_bits {
            None => first_bits = Some(bits),
            Some(b) => assert_eq!(
                bits, b,
                "backend {} disagreed on 0.1 + 0.2 bit pattern",
                backend.name(),
            ),
        }
    }
}
```

This is the determinism promise in action: `0.1f32 + 0.2f32`
produces the same bits on every backend, always, forever.

## Testing approximate track

Approximate track tests assert results within a ULP tolerance.
The tolerance is declared per operation:

```rust
/// Approximate sine produces results within 4 ULP of the exact value.
/// Oracle: exact IEEE 754 sine computed in host code.
#[test]
fn test_sine_approximate_within_four_ulp() {
    let inputs = [0.0f32, 0.5, 1.0, 1.5, 2.0, std::f32::consts::PI];

    for &input in &inputs {
        let program = build_sine_approx(input);
        let result = run_on_default_backend(&program).expect("dispatch");
        let exact = input.sin();

        let ulp_diff = ulp_distance(result, exact);
        assert!(
            ulp_diff <= 4,
            "sine({}) produced {}, expected {}, diff {} ULP",
            input, result, exact, ulp_diff,
        );
    }
}
```

The `ulp_distance` helper computes the number of ULPs between
two floats. The assertion says the result is within 4 ULP of
the exact value. A bug that produces 100 ULP error would fail
this test; a 1 ULP error passes.

The approximate track's tolerance is the oracle. The specific
tolerance per operation is in the approximate track's spec
table, analogous to the strict track's spec table but with
tolerances instead of exact values.

## Edge cases

Floating-point has specific edge cases that must be tested:

### Subnormals

Subnormal numbers are very small floats below the normal range.
Many GPU backends flush subnormals to zero by default (for
speed), which is non-conformant. vyre's strict track requires
subnormal preservation.

```rust
#[test]
fn test_add_f32_subnormal_strict() {
    let a = f32::from_bits(0x00000001);  // smallest positive subnormal
    let b = f32::from_bits(0x00000001);
    let program = build_single_fadd(a, b);
    let result = run_on_default_backend(&program).expect("dispatch");
    let expected = f32::from_bits(0x00000002);  // 2x smallest subnormal
    assert_eq!(result.to_bits(), expected.to_bits());
}
```

The test asserts that adding two subnormals produces the
correct subnormal result, not zero. A backend that flushes
subnormals would fail this test.

### NaN

NaN values have specific bit patterns, and some operations
propagate NaN while others do not. vyre's specification pins
down the expected NaN behavior.

```rust
#[test]
fn test_add_f32_nan_propagates_strict() {
    let nan = f32::NAN;
    let program = build_single_fadd(nan, 1.0f32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert!(result.is_nan(), "NaN + 1.0 should be NaN");
}
```

NaN has many bit patterns (quiet NaN, signaling NaN, different
payload bits). The test uses `is_nan()` rather than bit
comparison because vyre's spec says "produces a NaN," not
"produces this specific NaN bit pattern" (the specific pattern
is backend-dependent).

For tests that assert the NaN bit pattern is preserved through
round-trip, the assertion is stricter:

```rust
#[test]
fn test_nan_bit_pattern_roundtrips_through_wire_format() {
    let nan = f32::from_bits(0x7FC01234);  // specific NaN payload
    let program = build_program_with_f32_constant(nan);
    let bytes = Program::to_wire(&program);
    let decoded = Program::from_wire(&bytes).unwrap();
    let constant = extract_f32_constant(&decoded);
    assert_eq!(
        constant.to_bits(), nan.to_bits(),
        "NaN bit pattern should round-trip exactly",
    );
}
```

### Infinity

Positive and negative infinity have specific behaviors. `inf
+ -inf` is `NaN`. `inf * 0.0` is `NaN`. `inf + 1.0` is `inf`.
Each has a spec and a test.

### Signed zero

`+0.0` and `-0.0` are distinct in IEEE 754 but compare equal.
vyre tests that operations preserve the sign of zero where
the spec requires it.

```rust
#[test]
fn test_negate_positive_zero_produces_negative_zero() {
    let program = build_single_negate(0.0f32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result.to_bits(), (-0.0f32).to_bits());
}
```

### Round-to-even

Float operations round to the nearest representable value,
with ties going to even. A backend that rounds differently
(round up, round down, round to zero) produces wrong results
on cases where the true value is exactly between two
representable floats.

```rust
#[test]
fn test_add_f32_round_to_even_exact_tie() {
    // Inputs chosen so the exact sum is exactly between two
    // representable f32 values, and round-to-even picks the
    // even one.
    let a = f32::from_bits(0x3F800001);  // 1.0 + 1 ULP
    let b = f32::from_bits(0x34000000);  // 2^-23
    let program = build_single_fadd(a, b);
    let result = run_on_default_backend(&program).expect("dispatch");
    // Expected: round to even picks the even mantissa.
    let expected = f32::from_bits(0x3F800002);
    assert_eq!(result.to_bits(), expected.to_bits());
}
```

This test specifically catches backends that use
round-to-nearest-away-from-zero instead of round-to-even.

## The worst-case test

Beyond edge cases, vyre has "worst-case" tests that use inputs
known to stress float precision:

- **Catastrophic cancellation:** subtracting nearly-equal
  values to produce a tiny result with large relative error.
- **Catastrophic addition:** adding very different magnitudes
  where the smaller is lost in the rounding.
- **Transcendental worst cases:** inputs for which the
  transcendental function's approximation is at the edge of
  its accuracy guarantee.

Each of these is a canonical example in numerical analysis,
and each has a test in vyre's suite because the examples are
the cases that expose float implementation bugs.

## Float lowering tests

vyre's lowering has specific responsibilities for float
operations:

- **Emit `NoContract` pragmas** (or equivalent) to prevent the
  backend from fusing multiply-add.
- **Emit strict rounding** for operations that have non-strict
  fast paths.
- **Emit explicit subnormal handling** for operations that
  might flush.

The lowering tests verify these emissions:

```rust
#[test]
fn test_lower_fadd_emits_no_contract() {
    let program = build_single_fadd(1.0f32, 2.0f32);
    let shader = wgsl::lower(&program).expect("lowering succeeds");

    // WGSL does not have a standard no-contract pragma in all
    // versions, but vyre's lowering uses a workaround that
    // prevents fusion. The exact check depends on the
    // workaround.
    assert!(
        shader.contains("/* no-contract */"),
        "lowered FAdd should contain no-contract marker, got:\n{}",
        shader,
    );
}
```

The specific marker or pragma depends on the lowering
implementation. The test asserts the marker is present. A
mutation that removes the marker fails the test.

## The approximate track table

For each approximate operation, vyre maintains a tolerance
table that specifies the allowed ULP error:

```rust
pub const APPROXIMATE_TOLERANCE_TABLE: &[(OpName, Ulp)] = &[
    (OpName("approx_sine_f32"), Ulp(4)),
    (OpName("approx_cosine_f32"), Ulp(4)),
    (OpName("approx_reciprocal_f32"), Ulp(2)),
    (OpName("approx_rsqrt_f32"), Ulp(2)),
    // ...
];
```

The tolerance is part of the spec. A backend that produces
more error than the tolerance is non-conformant. A backend
that produces less error is still conformant (producing more
accurate results than required is not a violation).

Tests in the approximate track look up the tolerance from the
table and assert the result is within it.

## Summary

Float testing in vyre uses two tracks: strict (byte-identical
across backends) and approximate (within a declared ULP
tolerance). Edge cases (subnormals, NaN, infinity, signed
zero, round-to-even) are tested explicitly. Worst-case inputs
(catastrophic cancellation, transcendental edges) exercise
precision limits. Lowering tests verify the emission of
no-contract markers and strict rounding pragmas. The
discipline is the only defense against silent float drift
across backends.

Next: [Cross-backend equivalence in practice](cross-backend.md).
