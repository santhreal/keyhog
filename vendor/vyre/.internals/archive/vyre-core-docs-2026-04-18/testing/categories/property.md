# Property tests

## The difference between a specific test and a property

A specific test pins down one input and one expected output.
"Add of (u32::MAX, 1) equals 0." It proves that for this exact
input, the code produces the correct answer. It catches bugs that
affect that exact input. If the code has a bug that only fires
for other inputs, the specific test misses it.

A property test asserts a universal claim: "for every input `a`
and every input `b`, `add(a, b) equals add(b, a)`." It does not
pin down any specific input. It does not produce an expected
output for any specific value. What it does is generate a large
number of random inputs and check the claim on each. If any
generated input violates the claim, the test fails, and proptest
automatically shrinks the failing input to the minimal case that
still violates the property.

Specific tests and property tests are complementary. Specific
tests catch known bugs in known inputs. Property tests catch
unknown bugs in unknown inputs. Both are necessary; neither is
sufficient alone. vyre's suite uses both, and the category
described in this chapter is where the property tests live.

## Where proptest fits in

The Rust ecosystem has two major property testing libraries:
`quickcheck` and `proptest`. vyre uses `proptest` for every
property test. The choice is deliberate: proptest has better
shrinking, better seed management, better integration with the
test harness, and a more active development community. Every
property test in vyre is a `proptest!` block with a fixed seed,
a case count appropriate to the CI tier, and an assertion that is
a universal claim about vyre's behavior.

```rust
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    })]

    /// IR wire format round-trip is identity for every valid Program.
    /// Oracle: I4 (IR wire format round-trip identity).
    #[test]
    fn wire_format_roundtrip_is_identity(program in arb_program()) {
        let bytes = Program::to_wire(&program);
        let decoded = Program::from_wire(&bytes).unwrap();
        prop_assert_eq!(program, decoded);
    }
}
```

The block declares:

- A `ProptestConfig` with explicit case count and shrink
  iterations. 10,000 cases is the standard for CI runs; release
  CI uses 100,000; nightly uses 1,000,000. The `#[cfg_attr(...)]`
  and `#[ignore]` patterns control which run executes which
  count.
- A generator (`arb_program()`) that produces random valid
  Programs. The generator is the most important part of the
  test and gets its own section below.
- A test function body that runs the property on the generated
  input and asserts with `prop_assert_eq!` — proptest's version
  of `assert_eq!` that integrates with shrinking.

When the test runs, proptest calls `arb_program()` thousands of
times, feeds each Program to the test body, and records any
failures. On a failure, proptest shrinks the Program to the
smallest case that still fails the property and prints the
shrunk input.

## The structure of the category

```
tests/property/
├── determinism.rs           I1: same inputs → same outputs
├── wire_format_roundtrip.rs    I4: roundtrip is identity
├── validation_soundness.rs  I5: validated → safe to lower
├── lowering_invariants.rs   Lowering produces valid WGSL for validated Programs
├── law_preservation.rs      I7: composition preserves laws
└── backend_equivalence.rs   I3: backends agree on random Programs
```

One file per invariant. The file contains one or a small number
of proptest blocks, each asserting one specific instance of the
invariant.

## Generators

A property test is only as strong as its input generator. A
generator that produces trivial inputs catches only trivial bugs.
A generator that produces inputs matching the shape of real
Programs catches real bugs. The challenge is writing generators
that produce inputs that are *structured* — that have the shape
of something vyre actually sees — rather than *flat* — random
bytes that happen to parse.

For `ir::Program`, the flat approach would be "generate a
`Vec<u8>`, interpret it as wire format, discard the ones that do not
decode." This approach produces some inputs but they are mostly
rejected and the inputs that survive are heavily biased toward
short, simple Programs. Deep structural bugs in Programs with
loops, composition, and control flow are almost never exercised.

The structural approach is "generate an `ir::Program` directly
by constructing a tree of nodes from a grammar." This approach
is more work (you have to write the grammar) but produces inputs
that match real Programs in distribution. Structural generators
are what vyre uses.

### Writing a structural generator

```rust
use proptest::prelude::*;

pub fn arb_program() -> impl Strategy<Value = Program> {
    (1..5usize, 1..10u32).prop_flat_map(|(num_buffers, workgroup_size)| {
        let buffers = prop::collection::vec(arb_buffer_decl(), num_buffers);
        let entry = arb_node(Depth::new(4));
        (buffers, Just(workgroup_size), entry)
            .prop_map(|(buffers, workgroup_size, entry)| Program {
                buffers,
                workgroup_size,
                entry,
            })
    })
}

pub fn arb_buffer_decl() -> impl Strategy<Value = BufferDecl> {
    (
        arb_identifier(),
        arb_data_type(),
        1u32..1024,
    ).prop_map(|(name, data_type, count)| BufferDecl {
        name,
        data_type,
        count,
        access: BufferAccess::ReadWrite,
        binding: 0,
    })
}

pub fn arb_node(depth: Depth) -> impl Strategy<Value = Node> {
    let base = prop_oneof![
        Just(Node::Return),
        Just(Node::Nop),
    ];

    if depth.exhausted() {
        return base.boxed();
    }

    let recursive = {
        let inner = arb_node(depth.decrement());
        prop_oneof![
            base,
            (arb_expr(), inner.clone(), inner.clone().prop_map(Some).boxed())
                .prop_map(|(cond, then, else_)| Node::If {
                    cond,
                    then: Box::new(then),
                    else_: else_.map(Box::new),
                }),
            // ... loops, composition, etc.
        ]
    };

    recursive.boxed()
}
```

The generator is recursive because `Node` is recursive (nodes
contain nested nodes). Recursion is bounded by a `Depth` counter
that decrements on each nested call. When `Depth::exhausted`
returns true, the generator falls back to a base case (a `Return`
or a `Nop`) rather than continuing to recurse indefinitely.
Without depth bounding, the generator would produce Programs
too deeply nested to terminate; with depth bounding, it produces
Programs that are bounded but still diverse.

The generator uses `prop_oneof!` to pick between alternatives
with weighted probabilities. Simple nodes (Return, Nop) are more
likely than complex ones (If, Loop) so the average generated
Program has manageable size. Without weighting, the generator
produces Programs that are almost all complex, which makes
shrinking slow and debugging hard.

### Generator discipline

A good generator:

- **Is bounded in depth.** Recursive generators use a depth
  counter that decrements on each recursion. When exhausted, the
  generator falls back to a base case.
- **Is bounded in width.** Lists and collections have explicit
  size bounds. Unbounded collections produce Programs too large
  to test efficiently.
- **Produces valid inputs.** The generator's output must pass
  the validator. An invalid input is not interesting for
  testing the pipeline because it will be rejected before any
  of the later stages run.
- **Covers rare variants.** The generator explicitly handles
  rare `Expr` and `Node` variants (atomics, workgroup memory,
  nested loops) so property tests exercise them. Without
  explicit handling, rare variants appear with probability near
  zero and are effectively untested.
- **Is reproducible from a seed.** Given a fixed seed, the
  generator produces the same sequence of Programs. This is
  essential for debugging: when a test fails, the maintainer
  can rerun the same seed and get the same failure.
- **Shrinks well.** proptest's shrinking relies on the generator
  producing values that can be made smaller. A generator that
  produces opaque structures that cannot be decomposed will not
  shrink, and failing cases will be large and hard to diagnose.

See [Property-based testing for GPU IR](../advanced/property-generators.md)
in Part VIII for a deeper treatment of generator design.

## Case counts across CI tiers

vyre runs property tests with different case counts depending on
the CI tier:

- **Per-commit CI:** 1,000 cases. Fast enough to run on every PR.
  Catches most common bugs.
- **Release CI:** 100,000 cases. Runs before releases. Catches
  rarer bugs that per-commit CI misses.
- **Nightly CI:** 1,000,000 cases. Catches the long tail of
  corner cases. Findings here become regression corpus entries.

The case count is set in `ProptestConfig`, and the higher counts
are gated by `#[ignore]` attributes so they only run when
explicitly invoked:

```rust
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn quick_roundtrip(program in arb_program()) {
        // 1,000 cases, runs in per-commit CI.
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 100_000,
        ..ProptestConfig::default()
    })]

    #[test]
    #[ignore] // only runs with `cargo test -- --ignored`
    fn thorough_roundtrip(program in arb_program()) {
        // 100,000 cases, runs in release CI.
    }
}
```

The release CI invokes `cargo test -- --ignored` to run the
thorough tests; the per-commit CI runs `cargo test` without
`--ignored` and skips them. Nightly runs a custom invocation
with a configured case count.

## Fixed seeds and regression corpus

Every property test in vyre has a fixed master seed. The seed is
set via an environment variable or via `ProptestConfig::fork`,
and it is committed so CI runs produce the same sequence of
inputs across machines.

When a proptest fails, proptest records the failing case in a
regression file at the crate root: `proptest-regressions/<test_name>.txt`.
The regression file contains the seed that reproduced the
failure and the shrunk counterexample. The file must be committed
so that future runs re-execute the regression case before
attempting any new cases. Without committing the regression file,
the failure can recur and look like a new bug each time.

The discipline:

1. Proptest fails on seed X with input Y.
2. proptest writes `proptest-regressions/<test>.txt` with seed X
   and input Y.
3. The contributor fixes the bug that caused the failure.
4. The contributor commits both the fix and the regression file.
5. Future runs of the test re-execute seed X first and assert the
   fix holds.

This is how property tests accumulate institutional memory: every
past failure becomes a permanent check, reproducing automatically
from the committed regression corpus.

See [Seed discipline](../discipline/seed-discipline.md) for the
complete treatment.

## What property tests verify

The invariants verified by the property category are:

- **I1 (determinism):** random Programs run twice produce
  identical output.
- **I3 (backend equivalence):** random Programs produce
  identical output on every registered backend.
- **I4 (IR wire format round-trip identity):** random Programs
  round-trip through wire format without loss.
- **I5 (validation soundness):** random Programs that pass
  validation can be lowered and dispatched without panic.
- **I7 (law monotonicity):** random compositions of ops with
  declared laws preserve those laws.

Each invariant has at least one property test, sometimes several
that stress it in different ways. The file layout in
`tests/property/` puts one invariant per file when possible.

## What property tests are not for

Property tests are not a substitute for specific-input tests.
Specific inputs expose bugs that random generation is unlikely
to find. For example, `(u32::MAX, 1)` is a specific input that
catches overflow bugs; a random generator might not produce
`u32::MAX` for millions of iterations. Specific tests for known
edge cases are always faster to write and more reliable than
hoping the generator hits them.

Property tests are not for "the code runs" checks. If the
assertion is `prop_assert!(result.is_ok())`, the property is too
weak and belongs in `tests/adversarial/` where "did not panic"
is the correct assertion.

Property tests are not for testing specific implementations.
"The output of this function equals this specific algorithm"
is a specific test, not a property. A property test's assertion
should be about vyre's semantics, not about vyre's implementation
details.

## The forall-shrink trap

The most common mistake in writing property tests is to write a
property that holds for the common case and silently fails on
edge cases that the generator happens not to produce. The
contributor writes `prop_assert!(buffer.len() > 0)` because
every generated buffer has at least one element; the test passes;
the property is accepted; the contributor moves on. Months later,
a user submits a Program with a zero-length buffer (which is
valid), the code path this test was meant to cover fires without
the assertion holding, and a bug reaches production.

The prevention is to include edge cases explicitly in the
generator. Zero-length buffers, empty Programs, Programs with
only return nodes — these are not "wrong" inputs; they are
valid inputs that the generator must produce occasionally so
that property tests exercise them. The rule of thumb: every
archetype from `vyre-conform/src/archetypes/` that applies to
the subject under test should be a potential output of the
generator.

## Summary

Property tests assert universal claims over large populations of
generated inputs. They use proptest, have fixed seeds, commit
regression corpora, run with different case counts across CI
tiers, and use structural generators that produce inputs
matching the shape of real Programs. Each property test
corresponds to one invariant. Together with specific-input
tests, property tests cover both known and unknown bug classes.

Next: [Backend tests](backend.md).
