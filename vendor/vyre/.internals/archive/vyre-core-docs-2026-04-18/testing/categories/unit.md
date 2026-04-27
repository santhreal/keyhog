# Unit tests

## What a unit test is in vyre

A unit test exercises a single function or a single data structure
in isolation, with no cross-module dependencies, no pipeline
invocation, and no Program construction. Unit tests are the
smallest, fastest, most narrowly scoped tests in vyre's suite.
They run in milliseconds, catch bugs that are too localized for
integration tests to notice, and exist to answer one question: does
this single function do what its signature claims it does?

Unit tests are not the main defense for any of vyre's invariants.
The invariants are all about system-level behavior — determinism,
backend equivalence, validation soundness, lowering fidelity —
and no single function, taken alone, can prove a system-level
invariant. Unit tests support the rest of the suite by ensuring
that when an integration test fails, the failure is not because
some trivial helper function was broken in a way the integration
test's oracle could not pinpoint.

The distinction matters because it determines how much work unit
tests should do and where they should live. A unit test that tries
to prove a system invariant is in the wrong place; that work
belongs to an integration test or a property test. A unit test
that just calls a function and asserts it returned `Some(_)`
without checking the inner value is too weak to justify its
existence. The useful unit test is the one that catches a specific
local bug that the larger suite would not otherwise notice.

## The preferred location

vyre's convention is that unit tests live inline with the code
they test, in a `#[cfg(test)] mod tests { ... }` block at the
bottom of the source file. The source file owns the function; the
test module is the function's companion.

```rust
// src/ir/wire/tag.rs

pub fn parse(byte: u8) -> Option<WireTag> {
    match byte {
        0x00 => Some(WireTag::Program),
        0x01 => Some(WireTag::BufferDecl),
        0x02 => Some(WireTag::Node),
        _    => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_byte_returns_some() {
        assert_eq!(parse(0x00), Some(WireTag::Program));
        assert_eq!(parse(0x01), Some(WireTag::BufferDecl));
    }

    #[test]
    fn parse_unknown_byte_returns_none() {
        assert_eq!(parse(0xFF), None);
    }
}
```

The inline module is the default. It keeps the test next to the
code, which is where a reader looks first when the test fails. It
has access to private items through `use super::*;`, which means
the test does not need to push helpers out of the private API just
to be testable. It compiles as part of the same crate, which means
the test-only code does not leak into consumers.

The `tests/unit/` directory exists as a fallback for the small
number of cases where the inline module is the wrong answer:

- Tests that need to observe behavior only visible across a crate
  boundary (for example, tests that need `extern crate vyre` to
  prove the public API compiles in isolation).
- Tests that need a separate target directory for some reason
  (for example, tests that interact with a feature-gated
  allocator without polluting the main compile).
- Tests that need to run as a standalone binary (rare; usually a
  sign the test actually belongs elsewhere).

When in doubt, use the inline module. The `tests/unit/` directory
should remain sparse. If it grows beyond a handful of files, that
is a signal that tests are being pushed there for organizational
reasons that would be better served by inline modules.

## What belongs in a unit test

A unit test is the right choice when every one of these is true:

- The subject is a single function or a single trait method or a
  single data-structure operation.
- The test can construct its inputs directly, without building an
  `ir::Program` or instantiating anything large.
- The oracle is obvious and local: the function's signature, a
  hand-written expected value, a parse-then-re-serialize round-trip
  on a small input.
- The assertion fits in a few lines.

Concrete examples that belong in unit tests:

- A test for `WireTag::parse(byte) -> Option<WireTag>` that verifies
  known bytes return the expected tags and unknown bytes return
  `None`. The function, the inputs, the expected outputs are all
  small and local.
- A test for `BufferAccess::is_read_only()` that constructs each
  `BufferAccess` variant and asserts the getter returns the
  expected boolean. No pipeline. No Program. Just the getter.
- A test for `ValidationError::display()` that constructs an error
  value directly, formats it, and asserts the string contains the
  expected elements. No validation run. Just the formatter.
- A test for a small pure helper in the wire format module that
  encodes a single field and verifies the byte layout.

## What does not belong

The easiest way to write a bad unit test is to let the subject
creep outward. A test that starts as "does this helper work"
drifts into "does this helper work when called from the real
code path, with real inputs, through the full pipeline" — and
suddenly the test is an integration test wearing a unit test's
clothes.

Reject any of these shapes from the unit category:

- **Tests that construct `ir::Program` values.** A Program is by
  definition bigger than a unit. If you are building a Program,
  your test belongs in `tests/integration/`.
- **Tests that call `lower::wgsl::lower()`.** Lowering is a
  pipeline stage; testing it involves at least a Program, which
  moves the test out of the unit category.
- **Tests that instantiate a backend.** Backends are heavyweight;
  tests that touch them are backend tests or integration tests.
- **Tests that exercise a function through a public API but could
  exercise it directly.** If the direct exercise is possible and
  the result is the same, use the direct exercise — it is more
  local, faster, and more obviously a unit test.
- **Tests that use `proptest!`.** Property tests belong in
  `tests/property/`, where the seed discipline and regression
  corpus rules apply. A random-input unit test in an inline
  module will eventually produce a failing seed that nobody
  commits, and the test will become a flake.

## The size of a unit test

Unit tests are small. A well-written unit test is under ten lines
of body, often under five. If a unit test is growing long, it is
usually because the subject function is doing too much and the
test is trying to cover every branch with one function. The fix is
to split the test, not to add helpers that hide the branches.

```rust
// WRONG — one test covering too many branches
#[test]
fn parse_all_bytes() {
    assert_eq!(parse(0x00), Some(WireTag::Program));
    assert_eq!(parse(0x01), Some(WireTag::BufferDecl));
    assert_eq!(parse(0x02), Some(WireTag::Node));
    assert_eq!(parse(0xFF), None);
    assert_eq!(parse(0xAA), None);
    assert_eq!(parse(0x7F), None);
}

// RIGHT — one test per property
#[test]
fn parse_program_byte_returns_program_tag() {
    assert_eq!(parse(0x00), Some(WireTag::Program));
}

#[test]
fn parse_buffer_decl_byte_returns_buffer_decl_tag() {
    assert_eq!(parse(0x01), Some(WireTag::BufferDecl));
}

#[test]
fn parse_unknown_bytes_return_none() {
    for byte in [0xFF, 0xAA, 0x7F] {
        assert_eq!(parse(byte), None);
    }
}
```

The split version has three tests where the kitchen-sink version
had one. When the split version fails, you see exactly which
property broke. When the kitchen-sink version fails, you see only
"parse_all_bytes failed" and have to read the output to figure out
which assertion inside the function tripped.

The last test uses a small loop because the property being
verified ("unknown bytes return None") covers a family of inputs,
and enumerating each in its own test would be noise. The rule of
thumb: when the property genuinely covers a family and the failure
mode is uniform across the family, a loop is fine. When each
element of the family is its own property with its own
consequences, split.

## Oracles in unit tests

Unit tests typically use one of two oracle kinds from the
[hierarchy](../oracles.md):

- **Hand-written expected values** (a degenerate case of
  Oracle 2, specification table, where the "table" is one row
  inline in the test). This is the most common oracle in unit
  tests: the author looked at the function, decided what the
  expected value should be, wrote it in the test.
- **CPU reference function** (Oracle 4). Rare in unit tests
  because unit tests usually exercise a function that has no
  separate reference. When they do — for example, when testing a
  helper that should agree with a standard library function —
  the standard library call serves as the reference.

The oracle must always be independent of the subject. The
simplest way to make a unit test fail its oracle rule is to copy
the function under test into the test module, rename it, and use
it to generate the expected value. That is a tautology and the
review checklist rejects it.

## Naming

Unit tests follow the same naming convention as the rest of the
suite: `test_<subject>_<property>`. Inside an inline module, the
subject is often omitted since it is implicit from the module
location. `fn parse_known_byte_returns_some` is equivalent to
`fn test_parse_known_byte_returns_some` when the module is
dedicated to the parser; the `test_` prefix is optional for inline
modules but required for files in `tests/unit/`.

See [Naming](../writing/naming.md) for the full convention.

## Failure messages

A unit test that fails should tell the reader what failed without
requiring them to read the test body. The easiest way to achieve
this is to include context in the assertion message:

```rust
#[test]
fn parse_every_known_byte_has_a_variant() {
    for (byte, expected) in KNOWN_BYTES {
        assert_eq!(
            parse(byte),
            Some(*expected),
            "parse({:#x}) should return Some({:?})",
            byte,
            expected,
        );
    }
}
```

The message turns a failing assertion into a useful diagnostic.
Without it, the reader sees `left: None, right: Some(Nop)` and has
to trace back to which iteration of the loop produced the failure.
With it, the reader sees the exact byte and expected variant.

Not every assertion needs a custom message. Single-assertion tests
can rely on the test name and the default message. Assertions
inside loops, inside helpers, or in contexts where the default
message would be ambiguous benefit from explicit messages.

## Performance expectations

Unit tests are expected to complete in milliseconds, ideally under
a millisecond each. A unit test that takes measurable time
suggests the subject is doing something the unit scope does not
cover: I/O, allocation on large inputs, pipeline invocation. Move
the test to the appropriate category.

The full unit suite should run in a few seconds at most. If it
does not, the suite has started to absorb tests that should have
been elsewhere, and the fix is to move them out.

## The contribution of unit tests to the suite

Unit tests catch a specific class of bug: local mistakes in
individual functions that would otherwise propagate to integration
tests with unhelpful failure messages. When a helper function
silently returns the wrong value, an integration test for the
system that uses that helper fails — but the failure points to
the integration, not to the helper. A unit test for the helper
fails instead, and points directly at the helper.

Without unit tests, debugging integration failures is harder: you
start with "the pipeline produced the wrong bytes" and have to
work backward through layers of abstraction to find the root
cause. With unit tests, the failure is localized to the helper
before you ever run the integration test, and you fix it in
place.

This is the quiet value of unit tests. They do not prove
invariants. They do not catch cross-module bugs. They make the
rest of the suite easier to debug when it fails, and they catch
trivial bugs before the rest of the suite ever has to.

## When unit tests are not enough

A subject tested only by unit tests is under-tested. Unit tests
verify that a function does what its signature claims; they do not
verify that the function is used correctly by the code that calls
it, or that the interaction between the function and the rest of
the system produces the expected outcome. Every unit-tested
subject of any importance should also appear in an integration
test that exercises it through the pipeline with a stronger
oracle.

If you find yourself writing only unit tests for a function — no
integration tests, no property tests — pause and ask: is the
function too small to matter, or is the function too important to
test only at the unit level? If the former, fine. If the latter,
the unit tests are a warmup, not a finish line.

## Summary

Unit tests are small, fast, isolated. They live inline with the
code they test. They catch local mistakes. They do not prove
invariants, and they are not a substitute for integration or
property tests. Use them where they fit; escalate to larger
categories when the subject grows.

Next: [Integration tests](integration.md) — the category where the
`ir::Program` pipeline lives and most hand-written correctness
coverage is built.
