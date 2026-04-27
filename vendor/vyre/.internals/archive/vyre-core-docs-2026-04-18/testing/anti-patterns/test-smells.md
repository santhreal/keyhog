# Test smells

## Subtler warning signs

The previous chapters in Part VI are about patterns that are
obviously wrong once you see them. A tautology is a tautology;
a kitchen sink is a kitchen sink; a seedless proptest is a
seedless proptest. Each has a clear definition and a clear
rejection rule.

Test smells are different. A smell is not a clear anti-pattern
but a warning sign that the test is drifting toward one. A
smelly test might still be correct, might still catch real
bugs, might still pass the review checklist. But the smell
suggests the test is not as strong as it could be, and catching
smells early prevents them from turning into anti-patterns
later.

This chapter is a catalog of smells. Each entry is a pattern
that is not automatically wrong but is worth examining when
you see it. If you can defend the pattern in review, the test
is fine. If you cannot, the smell has become a finding.

## Smell: the test asserts on the error message

```rust
#[test]
fn test_validate_rejects_bad_program() {
    let program = build_bad_program();
    let errors = validate(&program);
    assert_eq!(errors[0].message(), "duplicate buffer name 'foo'");
}
```

The test asserts a specific error message. The assertion
couples the test to the exact wording of the error, which is
implementation detail. If the message is reworded (for
localization, for clarity, for length), the test fails even
though the behavior is unchanged.

**Why it smells:** error messages are not part of vyre's
contract with its consumers. Consumers check error codes and
rules, not message text. Tests that check message text are
testing a non-contract surface.

**Fix:** assert on the error rule, not the message.

```rust
assert_eq!(errors[0].rule, ValidationRule::V001);
```

The exception: if the test is specifically about error message
formatting (for example, a test in `tests/unit/` for the
`Display` impl of `ValidationError`), then asserting on the
message is correct. The message is the subject.

## Smell: the test uses `.unwrap()` without context

```rust
#[test]
fn test_something() {
    let program = build_program();
    let shader = wgsl::lower(&program).unwrap();
    // ...
}
```

The `.unwrap()` will panic if lowering fails. The panic
message from unwrap is generic: "called `Result::unwrap()` on
an `Err` value". The maintainer debugging the failure has to
open the source to figure out what was being unwrapped and
what went wrong.

**Why it smells:** unwrap loses information. A test that
unwraps without context is harder to debug when the unwrap
fails.

**Fix:** use `.expect("what was expected")`:

```rust
let shader = wgsl::lower(&program).expect("lowering should succeed");
```

The expect message is shown in the panic, which makes the
failure diagnosable without opening the source.

## Smell: hardcoded magic numbers with no comment

```rust
#[test]
fn test_something() {
    let program = build_program_with_count(42);
    let result = run_on_default_backend(&program).unwrap();
    assert_eq!(result, 0xCAFE_BABE);
}
```

The numbers `42` and `0xCAFE_BABE` appear in the test without
explanation. The reader does not know why 42 is the count or
why the expected is 0xCAFEBABE.

**Why it smells:** magic numbers without context make the test
harder to understand. The reader has to guess at the intent.

**Fix:** add a comment or use a named constant:

```rust
// 42 is chosen to exercise the "one above half the limit" case
// where the buffer allocation path differs from the small-buffer case.
let program = build_program_with_count(42);
let result = run_on_default_backend(&program).unwrap();
// 0xCAFEBABE is the expected bit pattern when 42 elements are
// processed through the canonical hash function.
assert_eq!(result, 0xCAFE_BABE);
```

Or pull the constants into the test name and a descriptive
comment at the top of the file. Either makes the numbers
explicable without guessing.

## Smell: the test relies on ordering of iteration

```rust
#[test]
fn test_validate_finds_all_errors() {
    let program = build_program_with_three_violations();
    let errors = validate(&program);
    assert_eq!(errors[0].rule, ValidationRule::V001);
    assert_eq!(errors[1].rule, ValidationRule::V005);
    assert_eq!(errors[2].rule, ValidationRule::V010);
}
```

The test asserts the order in which the validator reports
errors. The validator's implementation determines the order,
and the order might change across versions even if the set of
errors is correct.

**Why it smells:** the assertion is coupled to an
implementation detail (iteration order) that is not part of
the contract.

**Fix:** assert on the set of errors, not the sequence:

```rust
let error_rules: HashSet<_> = errors.iter().map(|e| e.rule).collect();
assert_eq!(
    error_rules,
    HashSet::from([
        ValidationRule::V001,
        ValidationRule::V005,
        ValidationRule::V010,
    ]),
);
```

The set form is order-independent and matches the contract
(the validator reports these errors) without the incidental
coupling.

## Smell: the test uses `#[ignore]` without explanation

```rust
#[test]
#[ignore]
fn test_expensive_thing() {
    // ...
}
```

The `#[ignore]` attribute marks the test to be skipped by
default. A test that is ignored without explanation suggests
the test is broken or slow or flaky, and nobody knows which.

**Why it smells:** ignored tests accumulate. Over time, the
suite has tests that nobody runs and nobody maintains. They
might pass if run, or they might have been broken for months.

**Fix:** add a comment explaining why the test is ignored and
when it runs:

```rust
/// Runs only in release CI via `cargo test -- --ignored`.
/// Takes ~30 seconds because the case count is 100k.
#[test]
#[ignore]
fn thorough_roundtrip(program in arb_program()) {
    // ...
}
```

Or, if the test is ignored because it is broken, either fix
the test or delete it. A broken test that is ignored is worse
than a deleted test; it pretends to exist and provides no
coverage.

## Smell: the test constructs a Program from raw struct fields

```rust
#[test]
fn test_something() {
    let program = Program {
        buffers: vec![
            BufferDecl {
                name: "foo".into(),
                data_type: DataType::U32,
                count: 1,
                access: BufferAccess::ReadWrite,
                binding: 0,
                initial: None,
            },
            // ... more
        ],
        workgroup_size: 1,
        entry: Node::Return,
    };
    // ...
}
```

The test constructs `Program` by filling in every field of
the struct directly. This is verbose, couples the test to the
exact field layout, and makes the test fragile: adding a field
to `Program` breaks every test that constructs it this way.

**Why it smells:** direct struct construction is a leak of
implementation detail into tests. Builders and helpers exist
precisely to insulate tests from this.

**Fix:** use the builder API or a factory helper:

```rust
let program = Program::builder()
    .buffer("foo", DataType::U32, 1)
    .return_()
    .build();
```

Or use `build_single_binop` or another factory from
`tests/support/programs.rs`.

## Smell: the test uses `let _ = ...` for side effects

```rust
#[test]
fn test_something() {
    let program = build_program();
    let _ = validate(&program);
    let _ = wgsl::lower(&program);
    // no assertions after
}
```

The `let _ =` discards results. If the test has no assertions
after these calls, the test is the "doesn't crash"
anti-pattern. If the test has assertions after, the `let _ =`
is a red flag — the test might be relying on side effects
that are supposed to happen in `validate` or `lower`.

**Why it smells:** discarding results is a sign the test does
not care about them, which is usually wrong. Either care about
the result (assert on it) or remove the call (if it was
unnecessary).

**Fix:** assert on the result, or remove the call.

## Smell: the test has more setup than assertion

```rust
#[test]
fn test_something() {
    // 30 lines of Program construction...
    let mut program = Program::empty();
    // ... many calls ...

    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 42);
}
```

A test where the setup is 30 lines and the assertion is one
line is doing too much setup. The setup is either a sign that
the test should use a helper, or a sign that the Program shape
is unusual and deserves its own factory.

**Why it smells:** long setup is hard to read. A reader skims
30 lines of setup to find the one assertion, and the effort
overshadows the test's content.

**Fix:** extract setup into a factory helper. Give the helper
a descriptive name. The test body becomes a few lines with the
subject and assertion visible.

## Smell: the test uses `format!` in the assertion

```rust
assert_eq!(format!("{:?}", result), "U32(42)");
```

The assertion compares debug formatting output, which couples
the test to the exact `Debug` impl. Rust's debug format is not
part of the contract; it can change between versions of the
library.

**Why it smells:** debug formatting is an implementation
detail. Tests should assert on values, not on their debug
representations.

**Fix:** assert on the value directly:

```rust
assert_eq!(result, Value::U32(42));
```

If the test specifically needs to check formatting (for
example, a `Display` impl test), that is a different subject
and the test belongs in `tests/unit/` with a clear framing.

## Smell: the test does not use the naming convention

```rust
#[test]
fn add_test() { }  // too short
#[test]
fn test_Add_Overflow() { }  // wrong case
#[test]
fn test_add_works_correctly_for_most_inputs() { }  // vague
```

The test names do not follow `test_<subject>_<property>`. They
might still work in isolation, but they break the navigability
of the suite at scale.

**Why it smells:** non-conforming names make it hard to find
tests by substring, hard to identify failing tests by name,
and hard to maintain consistency across the suite.

**Fix:** apply [the naming convention](../writing/naming.md).

## Smell: inconsistent test density across files

One file has thirty tests for one op. Another file has two
tests for an op of similar complexity. The asymmetry suggests
either one file is over-tested or the other is under-tested.

**Why it smells:** uneven coverage is a sign of uneven
discipline. Either the overtested file has redundant tests
(which should be consolidated) or the undertested file has
gaps (which should be filled).

**Fix:** check the mutation gate for the undertested file. If
mutations survive, add tests. If mutations are all killed, the
file is fine despite being small, and the overtested file may
be the one with redundancy.

## How to use this chapter

Read the list. When reviewing a PR, keep the smells in mind.
Name any smell you see; do not just react with "this feels
off." A named smell is actionable; a vague unease is not.

When writing your own tests, run through the list before
committing. If any smell applies, consider whether it is
justified. Justified smells (with explicit rationale) are
acceptable. Unjustified smells are fixed before commit.

## Summary

Test smells are subtle warning signs that a test is drifting
toward an anti-pattern. They include: error message
assertions, unwraps without context, unnamed magic numbers,
order-dependent assertions, unexplained `#[ignore]`, direct
struct construction, discarded results, overlong setup, debug
format assertions, non-conforming names, and uneven coverage.
Each smell is not automatically wrong but is worth a second
look. Catching smells early prevents full anti-patterns from
entering the suite.

This concludes Part VI. Part VII is the discipline chapter
— the rules that keep the suite honest over time.

Next: Part VII opens with [The review checklist](../discipline/review-checklist.md).
