# Oracles

## The question every test answers

Every test asserts that some observed behavior of the code matches
some expected behavior. The observed behavior comes from running the
code. The expected behavior comes from somewhere else — some source
of truth that exists independently of the code under test. That
source of truth is the oracle, and picking the right oracle is the
single most important decision you make when writing a test.

If you pick a weak oracle, your test passes when the code is wrong
and you never find out. If you pick an oracle derived from the code
itself, your test is a tautology and proves nothing. If you pick no
oracle at all — if your test simply runs the code and asserts it
"worked" — you have not written a test; you have written a ritual
that exercises the code without verifying it.

This chapter is about picking the right oracle. It is the longest
chapter in Part II because most broken tests we see in practice are
broken because their author picked the wrong oracle, or no oracle
at all, and did not realize it.

## What an oracle is

An oracle is an independent source of truth for what a test's
expected value should be. "Independent" here means specifically: not
derived from the code being tested. If the test is verifying that
`add(2, 3) == 5`, the number `5` must come from outside the
implementation of `add`. It can come from a hand-written specification
table. It can come from a mathematical law. It can come from a
reference implementation that is not the code under test. It can come
from an external corpus of hand-verified cases. It can come from a
human sitting down with a pencil and computing the answer. It must
not come from calling `add(2, 3)` and saving the result.

The reason is simple. If the number `5` comes from calling `add`,
then the test passes whenever `add(a, b) == add(a, b)` — which is
true for every possible implementation of `add`, including wrong
ones. The test cannot detect bugs because its expected value and its
observed value are the same value. It is a tautology dressed up as a
test.

This sounds obvious written out, and yet it is the single most
common failure mode in test suites written by people who are tired
or rushed or in a hurry to hit a coverage number. It is also the
single most common failure mode in tests written by language models,
which is why this chapter is written with agents in mind as much as
humans. If you are an agent reading this book, the one thing you
must internalize is: the expected value in an assertion does not
come from running the code under test. Ever.

## The hierarchy, in full

vyre organizes oracles into a strict hierarchy from strongest to
weakest. Every test declares which oracle it uses. When more than
one oracle is applicable, the test must use the strongest one. The
generator in vyre-conform enforces this mechanically: when it emits a
test, it selects the oracle by running down the hierarchy and
picking the first applicable one. Human-written tests follow the
same rule, enforced by review.

The hierarchy is:

1. **Algebraic law**
2. **Specification table**
3. **Reference interpreter**
4. **CPU reference function**
5. **Composition theorem**
6. **External corpus**
7. **Property**

The numbering is the strength order. 1 is the strongest, 7 is the
weakest. "Strongest" means: most resistant to false positives, most
immune to tautology, most likely to catch a bug introduced by a
change in the code.

### Oracle 1 — Algebraic law

An algebraic law is a mathematical property that an operation must
satisfy for every input. Addition over `u32` is commutative: for
every `a` and every `b`, `add(a, b) == add(b, a)`. That property is
a law. It does not depend on any specific value of `a` or `b`. It
does not depend on what `add` is implemented in terms of. It is true
of addition because addition is defined to be commutative, and any
implementation of addition that violates it is not implementing
addition.

Laws are the strongest possible oracles because they are not claims
about specific inputs — they are claims about the operation itself.
A test that asserts a law cannot be fooled by choosing clever inputs.
A test that asserts `add(a, b) == add(b, a)` for arbitrary `a` and
`b` proves commutativity for those inputs; taken together with an
algebra engine that has verified the law exhaustively on `u8` and
witnessed it on 100K random `u32` pairs, the law has been proven
mathematically, not just "tested."

vyre-conform's algebra engine verifies every declared law on every
op at build time. The verification provenance is recorded with the
law declaration:

```
DeclaredLaw {
    law: Law::Commutative,
    verified_by: Verification::ExhaustiveU8,
}
```

A test that uses the law as its oracle is leaning on that verification
— the test asserts the law holds for specific inputs, and the algebra
engine has already proven it holds for all inputs. The test cannot
fail for any reason other than a broken implementation, which is
exactly what a test should be.

Use an algebraic law oracle whenever:

- The operation has a declared law covering the property you want
  to test.
- The law has been verified by the algebra engine (the `Verification`
  field is populated, not empty).
- The inputs in your test belong to the domain the law was verified
  on.

Do not use an algebraic law oracle when:

- The operation does not declare the law (even if it feels true).
- The law is declared but not yet verified.
- The law is verified for a narrower type than the one your test
  uses (for example, `ExhaustiveU8` does not necessarily imply the
  law holds on `u64`).

The test itself is small and direct. It picks concrete inputs,
computes the law's prediction from those inputs, and asserts the
implementation agrees:

```rust
/// Commutativity law on BinOp::Add over u32.
/// Oracle: DeclaredLaw::Commutative, verified ExhaustiveU8 by
/// vyre-conform's algebra engine.
#[test]
fn test_add_commutative_dead_beef_cafe_babe() {
    let a = Value::U32(0xDEADBEEF);
    let b = Value::U32(0xCAFEBABE);
    let result_ab = run(&build_binop(BinOp::Add, a, b));
    let result_ba = run(&build_binop(BinOp::Add, b, a));
    assert_eq!(result_ab, result_ba);
}
```

The expected value comes from the law (`result_ab == result_ba`),
not from computing the sum. The test would fail immediately if the
implementation of `Add` stopped being commutative. It would not fail
if the implementation of `Add` is wrong in a way that preserves
commutativity — for example, if it returned `0` always. That is why
this test is paired with specification-table tests that pin down the
actual value, which is Oracle 2.

### Oracle 2 — Specification table

A specification table is a hand-written list of `(inputs, expected)`
rows authored by a human who sat down and decided that these specific
inputs must produce these specific outputs. Each row has a rationale
explaining why it is in the table. The rows are committed to vyre's
source tree under `vyre-conform/src/spec/tables/<op>.rs` and loaded
by the test generator and hand-written tests alike.

A specification table row is authoritative. When a test uses a table
row as its oracle and the implementation disagrees, the implementation
is wrong by definition. The table is the ground truth; the
implementation is being verified against it.

Table rows are the strongest oracle for specific inputs because a
human has looked at the input, reasoned about what the operation is
supposed to produce, written the expected value down, and attached a
rationale. Unlike a law, a table row does not require universal
quantification — it pins down a single answer for a single input.
Unlike a reference implementation, a table row is not generated by
running code; it is generated by thinking.

A canonical specification table entry for `BinOp::Add`:

```rust
SpecRow {
    inputs: &[Value::U32(u32::MAX), Value::U32(1)],
    expected: Value::U32(0),
    rationale: "u32::MAX + 1 wraps to 0. Oracle for overflow \
                behavior; any implementation that saturates, \
                panics, or returns u32::MAX has violated the \
                wrapping semantics of BinOp::Add.",
    source: SpecSource::HandWritten,
}
```

The row carries enough context that a reader five years from now can
understand why it exists. If the row starts failing and someone is
tempted to change the expected value to match the implementation,
the rationale is the argument against that change: the wrapping
behavior is the contract. Changing the expected to match a broken
implementation would break the contract.

Use a specification table oracle whenever:

- The specific inputs you want to test are listed in a table.
- The table row has a clear rationale.
- The rationale points at a real semantic requirement, not an
  incidental artifact of today's implementation.

Do not use a specification table oracle when:

- The inputs are not in the table — write a new row first, then
  write the test.
- A stronger oracle (Oracle 1) applies.

A specification-table test is structurally similar to a law test,
but the assertion pins down a specific value instead of asserting a
relation:

```rust
/// u32::MAX + 1 wraps to 0 (overflow behavior of BinOp::Add).
/// Oracle: SpecRow from vyre-conform/src/spec/tables/add.rs.
#[test]
fn test_add_overflow_u32_max_plus_one_equals_zero() {
    let program = build_binop(
        BinOp::Add,
        Value::U32(u32::MAX),
        Value::U32(1),
    );
    let result = run(&program);
    assert_eq!(result, Value::U32(0));
}
```

The expected value is `0`. It comes from the table, which got it
from a human who decided wrapping is the contract. It does not come
from calling `add(u32::MAX, 1)` and asserting the result equals
itself.

### Oracle 3 — Reference interpreter

The reference interpreter is a pure-Rust, obviously correct, slow
evaluator for `ir::Program` that lives in `vyre-conform/src/reference/`.
It handles every `Expr` variant, every `Node` variant, every `BinOp`,
every `UnOp`, every `AtomicOp`. It uses single-threaded sequential
semantics for atomics. It uses strict IEEE 754 arithmetic for floats.
It is not optimized, not parallelized, and not efficient — it is
designed to be so simple that correctness can be read off the code
rather than proven separately. It is the oracle for invariant I3
(backend equivalence) and the definition of what every op means
when composed into a Program.

The reference interpreter is weaker than a specification table for a
specific input (because the table row has a human rationale and the
interpreter does not), but stronger than the CPU reference function
at the Program level (because it exercises the whole IR, not a
single op in isolation). Tests that want to verify a full Program —
"this Program, with these inputs, should produce these outputs" —
use the reference interpreter as their oracle.

The canonical use of the reference interpreter is in backend
equivalence tests. For every registered backend, run the same
Program, diff the results against the reference interpreter. Any
backend that disagrees with the reference is incorrect:

```rust
/// Backend equivalence: every registered backend produces bytes
/// identical to the reference interpreter for a canonical program.
/// Oracle: reference interpreter in vyre-conform::reference.
#[test]
fn test_add_chain_agrees_across_backends() {
    let program = build_add_chain(&[1, 2, 3, 4, 5]);
    let expected = vyre_conform::reference::run(&program, &[]).unwrap();
    for backend in registered_backends() {
        let observed = backend.run(&program, &[]).unwrap();
        assert_eq!(
            observed, expected,
            "backend {} disagreed with reference interpreter",
            backend.name(),
        );
    }
}
```

The reference interpreter is also the fallback oracle for any test
that does not have a matching specification table row and wants to
verify a composed Program's output. Write the Program, run it
through the reference interpreter to get the expected, run it through
the backend to get the observed, assert equal.

Use a reference interpreter oracle whenever:

- The test exercises a composed Program, not a single op.
- A stronger oracle (law or specification table row) does not apply.
- The test is about cross-backend equivalence (which is essentially
  always the case for composed programs).

Do not use a reference interpreter oracle when:

- A specification table row covers the exact inputs. The table row
  is stronger because it records a human's intent.
- The operation has a law that pins down the property being tested.
  The law is stronger because it covers every input in its domain.

The reference interpreter is the workhorse oracle for composed
programs. Most tests in `tests/integration/` below the primitive-op
level use it.

### Oracle 4 — CPU reference function

Every primitive op in vyre has a CPU reference function in
`src/ops/primitive/<op>.rs`. This function is the op's semantic
definition in host Rust code: what does it mean to apply this op to
these values? The function is implemented in terms of plain Rust
operations and produces the same result the GPU backend is required
to produce. It is the source from which every other interpretation
of the op is derived.

The CPU reference function is weaker than the reference interpreter
because it only covers a single op in isolation, not a full Program.
It is stronger than external corpora and property assertions because
it is directly tied to the op's semantic specification.

Use a CPU reference function oracle whenever:

- The test exercises a single primitive op in isolation (not through
  a Program).
- The test is checking that the CPU implementation matches itself
  under some transformation (for example, that applying the op to
  two types produces equivalent results when one is a subtype of the
  other).
- No stronger oracle is applicable.

Do not use a CPU reference function oracle when:

- The test exercises a composed Program. Use the reference
  interpreter instead; it handles the composition.
- You are tempted to use it as a convenience because you don't want
  to write a specification table row. That is not a valid reason;
  write the table row.

### Oracle 5 — Composition theorem

vyre-conform's composition module proves theorems about how laws
propagate through composition. For example: if `f` is commutative and
`g` is commutative, then `h = compose(f, g)` may or may not be
commutative depending on how the composition is structured, and the
theorem states exactly which structures preserve commutativity. The
theorems are proved in the composition module and verified at build
time.

A composition theorem oracle is used when a test wants to verify
that a composed operation has some property, and the property
follows from the composition theorem applied to the component ops.
The test asserts the property on specific inputs; the composition
theorem guarantees the property holds universally.

Composition theorem oracles are weaker than laws because they require
the caller to know which theorem applies, and they are applicable
only to composed operations. They are stronger than external corpora
because they are mathematical, not empirical.

Use a composition theorem oracle whenever:

- The test exercises a composed operation whose property follows
  from the composition theorem applied to its components.
- The theorem has been verified in vyre-conform's composition module.

Do not use a composition theorem oracle when:

- A direct law applies to the composed operation itself (treat the
  composition as a single op with its own law).
- The composition is more complex than any proved theorem covers.
  In this case, use the reference interpreter instead and revisit
  whether the theorem needs to be extended.

### Oracle 6 — External corpus

An external corpus is a collection of `(input, expected)` pairs
assembled from outside vyre: past bug reproducers, upstream test
suites, hand-verified fixtures from the literature, conformance
test vectors published by specification bodies. These corpora are
authoritative for their specific inputs but do not generalize.

Use an external corpus oracle whenever:

- The test is reproducing a specific case from a known external
  source.
- The case is covered by a commit to `tests/regression/` or by a
  published conformance vector.

Do not use an external corpus oracle when:

- The test could use a stronger oracle. Corpora are fallbacks for
  cases where a specification, a law, or an interpreter is not yet
  available.
- The corpus entry does not have a source citation. Unsourced corpus
  entries are effectively tautologies; the source is what makes the
  entry authoritative.

External corpus tests are most common in `tests/regression/`, where
each file records a past bug with its inputs, its symptoms, and its
fix. The corpus entries in those files are the definition of "the
bug is fixed." A test in `tests/regression/2025-11-04-shl-thirty-two.rs`
contains the inputs that triggered the shift-by-32 bug, the expected
output after the fix, and a header comment citing the commit that
introduced the fix. The expected output is the oracle: it is
authoritative because the bug's fix committed it.

### Oracle 7 — Property

A property is a claim of the form "for every input in some domain, a
certain condition holds." Property tests are the weakest oracle
because they do not pin down specific expected values; they assert
relations. A typical property test might assert that `lower(program)`
produces valid WGSL for every random program, without asserting what
the WGSL looks like. Another might assert that `validate(program)`
never panics regardless of input, without asserting what errors it
returns.

Property tests are weak as oracles because passing a property test
does not prove the code is correct — it only proves that the code
has not violated the specific relation the test asserts. A broken
implementation that always returns a fixed correct-looking value
might pass a property test that only checks "the output is in
range."

Use a property oracle whenever:

- You want to stress a large input space to find bugs that escape
  specific-input testing.
- No stronger oracle applies — no law, no table, no interpreter, no
  corpus.
- The property you are asserting is actually a meaningful
  correctness claim, not just a restatement of the code's behavior.

Do not use a property oracle when:

- A stronger oracle is applicable. This is the most common mistake.
  If a law applies, use the law. If a table row exists, use the
  table.
- The property is "the code doesn't panic." That is not a test; it
  is a wish. Panic-free behavior is important, but it belongs in
  [adversarial tests](categories/adversarial.md), and even there
  the assertion is "the code returned a structured error instead of
  panicking," which is stronger than "the code didn't panic."

Property tests are specifically what `tests/property/` exists for.
Each file in that directory corresponds to one invariant, with a
proptest generator producing inputs and a single assertion verifying
the invariant. See [Property tests](categories/property.md) for the
full treatment.

## How to pick the oracle for your test

When you are about to write a test, you already know what code you
are testing and what property you are verifying. Picking the oracle
is a mechanical process:

1. Is there a declared and verified law on the operation that covers
   the property? → Use Oracle 1.
2. Is there a specification table row with the specific inputs you
   want to test? → Use Oracle 2.
3. Is the test a full Program, not a single op? → Use Oracle 3
   (reference interpreter).
4. Is the test a single op in isolation? → Use Oracle 4 (CPU
   reference function).
5. Is the composed operation's property proved by a composition
   theorem? → Use Oracle 5.
6. Is there an authoritative external source for the inputs? → Use
   Oracle 6.
7. Is the test a forall-style invariant? → Use Oracle 7 (property).

The rule is: walk down the list and stop at the first applicable
oracle. Do not skip. Do not use a weaker oracle when a stronger one
applies. The mutation gate enforces this at commit time; reviewers
enforce it at PR time; this book enforces it culturally.

## How the wrong oracle fails

The most dangerous failure mode in a test suite is not a test that
obviously fails. A test that fails loudly gets fixed. The dangerous
failure mode is a test that passes while the code is wrong — a
false positive in the "tests pass, ship it" sense.

A test with the wrong oracle is the most common source of this
failure mode. Here are the shapes it takes in practice:

**The tautology.** The expected value comes from calling the function
under test:
```rust
// WRONG — expected derived from code under test.
let expected = add(a, b);
let program = build_binop(BinOp::Add, Value::U32(a), Value::U32(b));
assert_eq!(run(&program), Value::U32(expected));
```
This test passes for every implementation of `add`, including `|a,
b| 0`. It is a tautology, not a test.

**The weak property.** The assertion is too loose to detect real bugs:
```rust
// WRONG — "output is some u32" is not a correctness claim.
let program = build_binop(BinOp::Add, a, b);
let result = run(&program);
assert!(matches!(result, Value::U32(_)));
```
This test passes for every implementation that returns a `u32`. It
is not verifying `Add`; it is verifying that the runtime can return
a value.

**The hidden tautology.** The expected value is derived from the
code under test through one level of indirection:
```rust
// WRONG — hidden behind a helper that itself calls the code under test.
fn expected_add(a: u32, b: u32) -> u32 { cpu::add(a, b) }
#[test]
fn test_add() {
    let program = build_binop(BinOp::Add, Value::U32(2), Value::U32(3));
    assert_eq!(run(&program), Value::U32(expected_add(2, 3)));
}
```
The helper `expected_add` calls `cpu::add`, which is exactly what the
backend is being tested against. This is a tautology with an extra
function call, not a real oracle.

**The stale table row.** The table row exists but its rationale is
wrong, and the expected value was derived from a broken
implementation long ago:
```
SpecRow {
    inputs: &[Value::U32(u32::MAX), Value::U32(1)],
    expected: Value::U32(u32::MAX),  // WRONG — should be 0
    rationale: "",                    // no rationale to catch the error
}
```
A rationale-less table row is a seed for tautology. The review rule
in this book is that every `SpecRow` has a rationale explaining why
its expected value is correct, independent of any implementation.
Rationaleless rows are rejected at review.

## The oracle declaration

Every test in vyre declares its oracle in a doc comment on the test
function:

```rust
/// <one-line description of what the test verifies>
/// Oracle: <which oracle, with a pointer to where it's defined>.
/// Rationale: <why this oracle, if not obvious>.
#[test]
fn test_name() { ... }
```

The declaration is not decorative. It is enforced by review. A test
without an oracle declaration is rejected. A test whose declared
oracle is weaker than the strongest applicable oracle is rejected.

The declaration is how a reviewer knows what to check. Without it,
the reviewer has to reverse-engineer the oracle from the test code,
which is the situation that produces the anti-patterns above. With
it, the reviewer checks: is this oracle the strongest applicable? Is
the test actually using it? Is the expected value actually coming
from where the declaration claims? If yes to all three, the oracle
is correct and the test can be evaluated on its other merits.

## Summary

An oracle is an independent source of truth for expected values.
Picking the right one is a mechanical process: walk the hierarchy,
use the first applicable. The hierarchy from strongest to weakest is
law, specification table, reference interpreter, CPU reference
function, composition theorem, external corpus, property. Every test
declares its oracle. Every declared oracle is the strongest
applicable. Tests that use weaker oracles when stronger ones exist
are rejected at review.

This is the single most important chapter of Part II. If you
understand oracle selection, you understand why vyre's suite looks
the way it does. If you do not, no amount of test categorization or
template discipline will save the suite from drift.

Next: [Mutations and the adversarial mindset](mutations.md) — what
it means to grade a test suite not by what it tests but by what it
can no longer hide.
