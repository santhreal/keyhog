# Starting with intent

## The question before the first test

When you sit down to write the test suite for a new op, the very
first question is not "what should I test?" It is "what does
this op mean?" Until you can answer that question precisely, any
tests you write are guesses. With a precise answer, the tests
almost write themselves — they are just enumerations of the
things you already know must be true.

This part of the book walks through the complete test set for
`BinOp::Add` over `u32`, from the first question to the final
mutation-gate-passing suite. `Add` is a good subject for this
exercise because it is simple enough that the reader can hold
all of it in their head at once, and complex enough that the
test set is non-trivial. Every primitive op in vyre follows the
same process. After reading this part, you will know how to
test any op by transposition.

We start with intent, because everything that follows depends
on it.

## What does `Add` mean?

`BinOp::Add` over `u32` is unsigned 32-bit addition with
wrapping overflow. That statement is one sentence long but
contains several commitments:

- **Binary.** It takes exactly two inputs.
- **Unsigned.** The inputs are interpreted as non-negative
  integers in `[0, 2^32)`.
- **32-bit.** The inputs and the output are exactly 32 bits wide.
- **Addition.** The output is the sum of the inputs, in the
  mathematical sense.
- **Wrapping.** When the mathematical sum exceeds the maximum
  representable value, the result is the sum modulo `2^32`.
- **Overflow is defined, not undefined.** `Add(u32::MAX, 1)` is
  `0`, not "undefined behavior" or "implementation-defined."

Each commitment is a testable property. Together they pin down
`Add` completely — any function matching all six claims is
indistinguishable from `Add` from the outside, and any function
matching fewer than six is not `Add`.

Writing this paragraph was the hardest part of testing `Add`.
Once we know exactly what `Add` means, every test we write is
an enumeration of these commitments in specific instances.

## The specification, in code

vyre records the meaning of each primitive op in a specification
entry in `vyre-conform/src/spec/ops/`. The entry has the same
commitments expressed as Rust data:

```rust
pub const ADD_SPEC: OpSpec = OpSpec {
    name: "add",
    category: Category::Intrinsic,
    signature: OpSignature {
        inputs: &[DataType::U32, DataType::U32],
        output: DataType::U32,
    },
    reference_fn: |args| {
        Value::U32(args[0].as_u32().wrapping_add(args[1].as_u32()))
    },
    laws: &[
        DeclaredLaw { law: Law::Commutative,        verified_by: Verification::ExhaustiveU8 },
        DeclaredLaw { law: Law::Associative,        verified_by: Verification::ExhaustiveU8 },
        DeclaredLaw { law: Law::Identity(Value::U32(0)), verified_by: Verification::ExhaustiveU8 },
    ],
    spec_table: ADD_SPEC_TABLE,
    archetypes: &[&A1_IdentityPair, &A2_OverflowPair, &A3_PowerOfTwoBoundary, &A5_BitPatternAlternation, &A7_SelfInverseTrigger],
    mutation_sensitivity: &[MutationClass::ArithmeticMutations, MutationClass::ConstantMutations],
    oracle_override: None,
    since_version: Version { major: 1, minor: 0, patch: 0 },
    category_c_fallback: None,
    docs_path: "docs/ops/primitive/add.md",
};
```

Every field in this struct is a commitment. The `name` names
the op. The `category` says it is compositional (Category A),
not a hardware intrinsic. The `signature` declares the input and
output types. The `reference_fn` is the authoritative Rust
implementation of `Add` — the function that every backend must
agree with. The `laws` list declares three algebraic properties
(commutativity, associativity, identity on zero), each verified
by the algebra engine exhaustively over `u8`. The `spec_table`
(defined below) lists specific `(inputs, expected)` pairs with
rationales. The `archetypes` list identifies the adversarial
input shapes that apply to `Add`. The `mutation_sensitivity`
list names the mutation classes the test suite must kill.

Every piece of this struct informs the test suite. The laws
become law tests. The spec table becomes specific-input tests.
The archetypes become archetype instantiations. The mutation
sensitivity tells us which mutations the gate will check and
which tests must kill them. Once the spec is complete, the test
suite is a mechanical consequence of the spec, with almost no
room for guesswork.

## The specification table

The spec table lists specific `(inputs, expected)` pairs for
`Add`:

```rust
pub const ADD_SPEC_TABLE: &[SpecRow] = &[
    SpecRow {
        inputs: &[Value::U32(0), Value::U32(0)],
        expected: Value::U32(0),
        rationale: "Identity pair: add(0, 0) = 0. Both operands \
                    are the identity element.",
        source: SpecSource::HandWritten,
    },
    SpecRow {
        inputs: &[Value::U32(0xDEADBEEF), Value::U32(0)],
        expected: Value::U32(0xDEADBEEF),
        rationale: "Right identity: add(x, 0) = x. Verifies the \
                    lowering handles the zero right operand \
                    without changing the left.",
        source: SpecSource::DerivedFromLaw(LawId::Identity),
    },
    SpecRow {
        inputs: &[Value::U32(0), Value::U32(0xCAFEBABE)],
        expected: Value::U32(0xCAFEBABE),
        rationale: "Left identity: add(0, x) = x.",
        source: SpecSource::DerivedFromLaw(LawId::Identity),
    },
    SpecRow {
        inputs: &[Value::U32(1), Value::U32(2)],
        expected: Value::U32(3),
        rationale: "Basic addition: add(1, 2) = 3. The simplest \
                    non-identity case.",
        source: SpecSource::HandWritten,
    },
    SpecRow {
        inputs: &[Value::U32(u32::MAX), Value::U32(1)],
        expected: Value::U32(0),
        rationale: "Overflow: u32::MAX + 1 wraps to 0. Pins down \
                    the wrapping semantics; any implementation \
                    that saturates, panics, or returns u32::MAX \
                    has violated the spec.",
        source: SpecSource::HandWritten,
    },
    SpecRow {
        inputs: &[Value::U32(u32::MAX), Value::U32(u32::MAX)],
        expected: Value::U32(u32::MAX - 1),
        rationale: "Double overflow: u32::MAX + u32::MAX = \
                    2 * u32::MAX, which modulo 2^32 is \
                    u32::MAX - 1. Verifies wrapping on multiple \
                    overflows.",
        source: SpecSource::HandWritten,
    },
    SpecRow {
        inputs: &[Value::U32(0x80000000), Value::U32(0x80000000)],
        expected: Value::U32(0),
        rationale: "Sign-bit boundary: 2^31 + 2^31 = 2^32 wraps \
                    to 0. Verifies the lowering does not confuse \
                    this with signed arithmetic.",
        source: SpecSource::HandWritten,
    },
    SpecRow {
        inputs: &[Value::U32(0x55555555), Value::U32(0xAAAAAAAA)],
        expected: Value::U32(0xFFFFFFFF),
        rationale: "Bit-pattern alternation: 0x55... + 0xAA... = \
                    0xFF... (complementary bit patterns fill the \
                    register). Any bit-flipping bug is obvious \
                    in the output.",
        source: SpecSource::HandWritten,
    },
    SpecRow {
        inputs: &[Value::U32(0xDEADBEEF), Value::U32(0xCAFEBABE)],
        expected: Value::U32(0xA9A8797D),
        rationale: "Adversarial inputs: 0xDEADBEEF + 0xCAFEBABE. \
                    Both bit patterns are distinctive; the \
                    expected value is computed once and committed.",
        source: SpecSource::HandWritten,
    },
    SpecRow {
        inputs: &[Value::U32(2_147_483_647), Value::U32(1)],
        expected: Value::U32(2_147_483_648),
        rationale: "i32::MAX + 1 = i32::MIN when interpreted as \
                    signed, but as u32 this is simply 2^31. \
                    Verifies the op treats operands as unsigned.",
        source: SpecSource::HandWritten,
    },
];
```

Ten rows. Each pins down one specific case with a rationale.
Together they cover: identity elements, basic arithmetic,
overflow, double overflow, sign boundary, bit-pattern adversarial
inputs, and the signed/unsigned distinction.

A contributor reading the spec table understands `Add` in the
specific inputs the table covers. A contributor adding a new
input to the spec table must explain why the new input matters
(the `rationale`) and where the expected value comes from (the
`source`). The table is the commitment that `Add` produces
these specific outputs, forever.

The computation `0xDEADBEEF + 0xCAFEBABE = 0xA9A8797D` was done
once, by hand, and checked. The value is in the table as a
committed number. Every test that uses this row asserts against
this exact value. If the computation were wrong, the test would
pass on broken code and fail on correct code — so the act of
writing down the expected value is itself a commitment to the
op's semantics, not just the op's implementation.

## The laws

`Add` declares three laws: commutativity, associativity, and
identity-on-zero.

**Commutativity** says `add(a, b) == add(b, a)` for every `a`
and every `b`. The algebra engine verifies this exhaustively on
`u8`: it tries every pair of `u8` values, applies `Add` in both
orders, and asserts the results match. If the engine ever
reports a counterexample, the law is broken and the declaration
cannot be made. The `Verification::ExhaustiveU8` provenance
records the verification and is required for the law declaration
to compile.

**Associativity** says `add(add(a, b), c) == add(a, add(b, c))`
for every `a`, `b`, `c`. Same verification: the algebra engine
checks all `u8` triples exhaustively.

**Identity on zero** says `add(x, 0) == x` and `add(0, x) == x`
for every `x`. The identity element is `0`, recorded in the
declaration as `Identity(Value::U32(0))`. Same verification.

Each law is a universal claim. Each claim has been
mathematically verified on a representative subset of the
domain. The tests that use these laws as oracles (law tests)
are leaning on this verification — they assert the law on
specific inputs, and the algebra engine has already proven the
law for all inputs.

## The archetypes

`Add` declares five archetypes: A1 (identity pair), A2 (overflow
pair), A3 (power-of-two boundary), A5 (bit-pattern alternation),
and A7 (self-inverse trigger).

Each archetype, when instantiated for `Add`, produces a set of
input tuples. A1 produces pairs where one or both operands are
0 (the identity). A2 produces pairs near the overflow boundary.
A3 produces pairs near powers of two. A5 produces pairs with
distinctive bit patterns. A7 produces pairs that exercise the
invertibility law — for `Add`, that is `add(x, -x) = 0`, but
since we are working in unsigned arithmetic, `-x` is the
wrapping negation, which is `0 - x` or `!x + 1`. The archetype
handles the instantiation automatically.

The archetypes are not part of the spec table. They are a
separate source of inputs, drawn from the archetype catalog and
applied to `Add` based on the signature match. The generated
tests that come from archetype instantiation are in addition to
the hand-written spec table tests.

## The mutation sensitivity

`Add` declares sensitivity to `ArithmeticMutations` and
`ConstantMutations`. These mutation classes are exactly the
mutations the test suite must kill when run against the `Add`
source. `ArithmeticMutations` includes swaps like
`BinOp::Add → BinOp::Sub`, `BinOp::Add → BinOp::Mul`, and
wrapping-to-saturating changes. `ConstantMutations` includes
constant increment/decrement.

The test suite is complete for `Add` when every mutation in
these two classes is killed by at least one test. The mutation
gate enforces this: a PR that modifies `Add` without tests that
kill the relevant mutations is rejected.

## What the intent phase gives us

By the time the specification is complete, we have:

- A precise statement of what `Add` means, in plain English.
- A Rust `OpSpec` encoding the meaning machine-readably.
- A `reference_fn` that is the authoritative implementation.
- A list of declared laws with their verifications.
- A spec table with ten specific-input rows and rationales.
- A list of applicable archetypes.
- A list of mutation classes the test suite must handle.

We have not written a single test yet. What we have is the
blueprint from which every test will be derived. The next
chapter writes the first test.

## A note on difficulty

Writing the intent down feels tedious the first time. It is not
tedious — it is most of the work. Contributors who skip this
step produce tests that feel correct until they hit a case the
contributor did not think of, and then the tests silently miss
the case. Contributors who take the time to write the intent
down produce tests that are complete because the intent
enumerated the cases.

If the intent phase feels like it is taking a long time, you are
doing it right. Spend the hour. Every subsequent test is faster
and more correct because the intent phase did the thinking up
front.

Next: [The first test](02-first-test.md) — writing
`test_add_identity_zero_spec_table` line by line, explaining
every decision.
