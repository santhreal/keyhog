# Support utilities

## The chapter is about writing helpers, not about the directory

Chapter 19 covered the `tests/support/` directory as a category:
what lives there, what the rules are, what the files are. This
chapter is about a different thing: how to write a helper when
the test you are working on needs one. The directory exists;
the question is what to put in it and what not to.

The guiding rule is the same one from chapter 19: helpers
exist to reduce boilerplate, not to obscure test intent. This
chapter expands that rule into practical guidance for the cases
that recur when writing tests.

## When to write a helper

The bar for writing a helper is that the same boilerplate
appears in three or more tests and obscures the tests' intent
when inlined. Two tests with shared setup do not need a helper;
you can copy the setup. Three tests start to look repetitive.
Four tests are repetitive. Five tests make a helper inevitable.

Helpers that solve one test's problem are anti-helpers. They
add indirection without reducing boilerplate because they are
only used once. If you are writing a helper for a single test,
stop and ask whether the code should be inlined in the test
instead.

Helpers that hide the test's subject, inputs, or expected value
are anti-helpers regardless of how many tests use them. A helper
that does `assert_test_case(test_case)` hides everything that
matters about the test. Reject it at review.

## What to put in a helper

A helper belongs in `tests/support/` when it reduces boilerplate
for several tests and the boilerplate is truly uninteresting at
the test's level of abstraction. Some examples:

- **Factory functions** for Programs with common shapes:
  `build_single_binop`, `build_program_with_loop`,
  `build_minimal_program_with_buffer`. Tests care about the
  shape the Program has; they do not care about the exact
  sequence of builder calls to produce it.
- **Runner wrappers** for dispatch: `run_on_default_backend`,
  `run_on_every_backend`. Tests care about the result; they do
  not care about the details of constructing a backend,
  dispatching, and unwrapping the result.
- **Assertion helpers** for strong oracles: `assert_agrees_with_reference`,
  `assert_law`, `spec_table_lookup`. These encapsulate the
  oracle lookup so the test can focus on the subject and
  property.
- **Fixture constants** for common values: `BIT_PATTERNS`,
  `ADD_OVERFLOW_PAIRS`. Tests that iterate over known values
  use the constants instead of duplicating the list in every
  test.

Each of these has a clear purpose, a clear name, and a clear
place in the file structure. The tests that use them read as
statements of intent, not as puzzles.

## How to write a helper that does not obscure intent

Three guidelines:

1. **Name the helper so a reader knows what it produces.** Not
   "create_test_data" but "build_single_binop". Not
   "run_test_case" but "run_on_default_backend". The name is
   the first layer of documentation.
2. **Take specific arguments, not configuration objects.** A
   helper with `BinOp` and two `u32` arguments is clear. A
   helper with a `TestCase` struct that has a builder is not.
3. **Return a concrete type, not a wrapped opaque result.**
   `Program` is clear. `TestCaseResult` is not.

Applied to a hypothetical helper for "build a Program that
computes `a + b` where both are random values from a
distribution":

```rust
// NO — hides subject and inputs
pub fn build_random_add_case(config: &TestConfig) -> Program {
    // ... produces a Program with some arguments determined by config
}

// YES — visible
pub fn build_add_with_random_inputs(seed: u64) -> (u32, u32, Program) {
    let mut rng = StdRng::seed_from_u64(seed);
    let a = rng.gen::<u32>();
    let b = rng.gen::<u32>();
    let program = build_single_binop(BinOp::Add, a, b);
    (a, b, program)
}
```

The second form returns the inputs along with the Program, so
the test can use them in the assertion. The first form hides
the inputs inside the config, and the test has to open the
config to know what is being tested.

## Helpers as documentation

A good test helper reads as a sentence. `run_on_default_backend(&program)`
reads as "run this program on the default backend." `build_single_binop(BinOp::Add, 1u32, 2u32)`
reads as "build a program with one add op of one and two." The
name plus the arguments tells the reader what is happening, and
the test body becomes a sequence of readable sentences.

If a helper's name plus its arguments does not read as a
sentence, the helper is wrong. Rename it, split it, or inline
it.

## Helpers that belong in production code, not in tests/support

Some helpers look like test helpers but should actually be in
vyre's source tree:

- **Convenience constructors for IR values.** If the test needs
  `Expr::from_u32(x)` and the main code also needs it, put it
  in `src/ir/expr.rs`, not in `tests/support/programs.rs`. Tests
  get it via the public API; the main code benefits from having
  it too.
- **Utility functions that could be public API.** If many tests
  call a helper to compute something that could be useful
  externally, promote it to the public API. Tests are a good
  place to discover missing API methods.
- **Iterators over IR structures.** Visitors and iterators are
  features of the IR, not test helpers. They belong in
  `src/ir/visit.rs`.

The rule of thumb: if the helper is useful to non-test code,
it probably belongs in the main crate. `tests/support/` is for
things that only make sense in a test context.

## Helpers that create test-only complexity

Avoid helpers that introduce test-only types or concepts that
have no meaning in the main crate:

- **Test case configuration structs** ("TestConfig",
  "TestScenario") are usually wrong. Tests should call helpers
  with specific arguments, not build opaque configuration.
- **Test runners** that iterate over collections of cases are
  usually wrong. If the tests have a common shape, use proptest
  or a parameterized test. If they have different shapes, write
  them as individual tests.
- **Test fixtures with complicated setup** are a sign the main
  crate lacks an API the tests need. Add the API.

The goal is that tests look like tests, not like test
frameworks. Every line of test code should be doing something
the test cares about, not setting up infrastructure.

## When to inline instead

Inline the code when:

- It is used in fewer than three tests.
- The code is so short that extracting it adds more overhead
  (cognitive and visual) than it saves.
- Inlining makes the test read more clearly, even at the cost
  of duplication.
- The code is specific to one test's intent and would not be
  useful to another test even in principle.

Inlined code is fine. Test code is not production code; some
duplication is acceptable if it makes the tests clearer. The
DRY principle applies less strictly to tests than to production
code because test code's primary value is being obvious, and
obviousness sometimes conflicts with compactness.

## Refactoring helpers

When a helper starts to feel wrong, it probably is. Refactor
pressures:

- **The helper has grown parameters.** A helper that started
  with two parameters and now has five is hiding something.
  Split it into smaller helpers.
- **The helper has special cases.** A helper with an `if
  config.special_mode` branch should probably be two helpers.
- **The helper's name has become inaccurate.** A helper called
  `build_simple_program` that actually builds complex programs
  needs a rename. The rename often exposes that the helper is
  doing too much.
- **The helper is used by exactly one test.** Delete the helper
  and inline it.

Refactoring helpers is low-risk because helpers are internal to
the test crate. The blast radius is small and the review is
easy. Do it whenever the pressure is there.

## Summary

Helpers exist to reduce boilerplate, not to hide intent. Write
them when three or more tests share setup. Name them
descriptively. Take specific arguments. Return concrete types.
Avoid configuration objects. Avoid test-only types that mimic
test frameworks. Inline when duplication is cheaper than
abstraction. Refactor when the helper starts to feel wrong.

Next: [Oracles in practice](oracles-in-practice.md) — applying
the oracle hierarchy to the tests you are actually writing.
