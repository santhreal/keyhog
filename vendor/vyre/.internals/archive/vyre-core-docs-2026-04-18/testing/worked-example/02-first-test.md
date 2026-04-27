# The first test

## Picking what to test first

With the intent phase complete, we know what `Add` means and
what we need to verify. We do not write all the tests at once.
We write them in order, starting with the simplest, so each
test teaches us something about the infrastructure and the
subsequent tests build on patterns established by the earlier
ones.

The simplest test for `Add` is the identity case: `add(0, 0) ==
0`. Both operands are the identity element. The arithmetic
involves no overflow, no bit manipulation, no complexity of any
kind. If this test fails, the entire pipeline for `Add` is
broken, and we want to know immediately. If this test passes,
we have a working baseline to build on.

The test we are about to write is
`test_add_identity_zero_spec_table`. The name encodes the
subject (`add`), the property (`identity_zero`), and the oracle
(`spec_table`). We will now write it line by line and explain
every decision.

## The file

The test goes in `vyre/tests/integration/primitive_ops/add.rs`.
The file is dedicated to tests for `BinOp::Add`. It already has
a module-level doc comment (written before any tests were
added):

```rust
//! Tests for BinOp::Add via the full ir::Program → lower →
//! dispatch path.
//!
//! Oracles used in this file:
//! - Specification table rows from vyre-conform::spec::tables::add.
//! - Algebraic laws verified by the vyre-conform algebra engine
//!   (Commutative, Associative, Identity(0)).
//! - Reference interpreter for composition and cross-backend.
//!
//! This file is the baseline hand-written suite for Add. Its
//! coverage must be strictly exceeded by the generated tests
//! from vyre-conform before the generator can supersede it.

use vyre::ir::{BinOp, Value};
use crate::support::programs::build_single_binop;
use crate::support::backends::run_on_default_backend;
```

The module comment tells the reader what the file is, what
oracles it uses, and what relationship it has with the
vyre-conform generator. The imports are minimal: just what we
need for the first test. As we add more tests, we add more
imports as needed.

## The test function

The first test is simple:

```rust
/// add(0, 0) == 0. Identity pair, both operands are the identity.
/// Oracle: SpecRow from vyre-conform::spec::tables::add (row 0).
#[test]
fn test_add_identity_zero_zero_spec_table() {
    let program = build_single_binop(BinOp::Add, 0u32, 0u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0u32, "add(0, 0) should equal 0");
}
```

Four lines of body. Let us go through every decision.

### The doc comment

The comment has two parts: a one-line description of what the
test verifies ("add(0, 0) == 0. Identity pair, both operands
are the identity.") and an oracle declaration ("Oracle: SpecRow
from vyre-conform::spec::tables::add (row 0).").

The description is specific. It names the exact inputs and the
exact expected output. A reader who sees the test name
`test_add_identity_zero_zero_spec_table` knows from the name
what the test does, but the comment confirms and adds the
property name ("identity pair"). When a reviewer asks "what is
this test verifying?" the first line of the comment is the
answer.

The oracle declaration is the other load-bearing line. It says
"the expected value 0 comes from row 0 of the spec table for
`Add`." A reviewer can open the spec table, look at row 0, and
verify it says `expected: Value::U32(0)`. If the spec table
disagrees with the test, one of them is wrong, and the reviewer
knows to investigate.

Without the oracle declaration, the reviewer would have to guess
where the expected value came from. Is it derived from running
`Add`? Is it from a specification table? Is it from a law? With
the declaration, the provenance is explicit and the test can be
evaluated.

### The test name

`test_add_identity_zero_zero_spec_table`. The pattern is
`test_<subject>_<property>_<oracle>`. The subject is `add`, the
property is `identity_zero_zero` (the inputs are both zero,
which is the identity), and the oracle is `spec_table`.

Why put the oracle in the name? Because when the test fails and
a maintainer reads the failure, they want to know immediately
which oracle is the authority. If the test is
`test_add_identity_zero_zero_spec_table`, the maintainer knows
to open the spec table and check row 0. If the test is
`test_add_identity_zero_zero_law`, the maintainer knows to check
the identity law declaration. Putting the oracle in the name
saves a lookup every time the test fires.

The name is long, but length is not a cost. Rust's test runner
handles long test names without issue, and `cargo test
<substring>` matches any substring of the name, so the long
form does not make the test harder to invoke.

### The `#[test]` attribute

Standard Rust. Nothing special.

### Line 1: construct the Program

```rust
let program = build_single_binop(BinOp::Add, 0u32, 0u32);
```

`build_single_binop` is a helper from `tests/support/programs.rs`
that constructs the smallest legal Program for a single binary
op. The helper's documentation says it creates a Program with
two input buffers (`a` and `b`), one output buffer (`out`), and
an entry node that loads from `a` and `b`, applies the op, and
stores to `out`.

The reader sees `build_single_binop(BinOp::Add, 0u32, 0u32)` and
understands: "build a Program that computes `Add` with inputs
0 and 0." The helper's name is descriptive, so the call site
reads as a statement of intent. The reader does not need to open
the helper to understand what it produces.

The inputs are typed as `u32`, not as `Value::U32(0)`. The
helper accepts raw Rust integers and wraps them in `Value::U32`
internally. This is a small convenience that makes the test
more readable: `0u32` is shorter than `Value::U32(0)`, and the
type annotation makes the bit width explicit.

### Line 2: run the Program

```rust
let result = run_on_default_backend(&program).expect("dispatch");
```

`run_on_default_backend` is a helper from
`tests/support/backends.rs` that dispatches the Program on the
default backend and returns the output. The default backend is
whatever `vyre::runtime::default_backend()` returns, which is
typically wgpu when the `gpu` feature is enabled, or the
reference interpreter otherwise.

The return type is `Result<u32, RuntimeError>` (for a Program
with a single `u32` output). We call `.expect("dispatch")` to
unwrap it, because a dispatch failure here is not a test
failure we want to tolerate — if dispatch fails, the test
cannot verify anything, and the `.expect` turns the failure
into a clear panic with message "dispatch failed: ...".

Note the message passed to `.expect` is short. It is not
"the dispatch of the test program failed for some unknown
reason"; it is just "dispatch". When the panic fires, the
Rust panic handler adds the file and line, so the full output
is "dispatch failed: <error>, at tests/integration/primitive_ops/add.rs:12".
That is enough context.

### Line 3: assert

```rust
assert_eq!(result, 0u32, "add(0, 0) should equal 0");
```

The assertion compares `result` (a `u32`) to `0u32` (the
expected value from the spec table row). `assert_eq!` with
three arguments takes an optional failure message, which here
is "add(0, 0) should equal 0".

The failure message is redundant with the test name — the test
is named `test_add_identity_zero_zero_spec_table`, which
already says what is being verified. But when the assertion
fails, the Rust test runner prints both the test name and the
assertion message, and having the message explicitly state what
was expected makes the output easier to scan. If a human is
reading a long test log trying to find what broke, the
assertion message stands out.

The expected value `0u32` is a literal. It is not computed from
anything. If we had written `assert_eq!(result, 0 + 0)` or
`assert_eq!(result, u32::wrapping_add(0, 0))`, we would be
deriving the expected from a computation, which is a tautology.
The literal `0u32` is the commitment: this is what we say `Add`
produces, and the test passes if and only if `Add` produces
exactly that.

## Running the test

From the `vyre` crate root:

```bash
cargo test -p vyre test_add_identity_zero_zero_spec_table
```

The test compiles, runs, and passes. Total time: a few hundred
milliseconds the first time (the compiler warms up), and
milliseconds on subsequent runs.

The test output is something like:

```
running 1 test
test test_add_identity_zero_zero_spec_table ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured
```

We have written our first test. It passes. We now know:

- The build pipeline is working for the test file.
- The helper imports resolve correctly.
- `build_single_binop` produces a valid Program.
- The default backend is registered and dispatches the Program.
- `BinOp::Add` on `(0u32, 0u32)` produces `0u32`, which matches
  the spec table.

Each of these is a fact we now depend on for subsequent tests.
If any were broken, this first test would have caught it, and
we would have fixed the broken thing before moving on.

## Why we started with this test

We started with the identity-zero case because:

- It is the simplest possible case. Both inputs are zero, the
  expected output is zero, no arithmetic happens that could
  fail.
- It is the most load-bearing case. If the pipeline cannot
  compute `0 + 0`, everything else is broken, and we want to
  know before writing nine more tests that all fail for the
  same reason.
- It exercises every stage of the pipeline (construction,
  validation, lowering, dispatch, result extraction) with
  minimal complexity in any stage.
- It establishes the file's infrastructure: imports, helper
  usage, assertion style, comment format. Subsequent tests
  reuse these patterns.

A maintainer who ever doubts whether the basic infrastructure
works runs this one test. If it passes, the basics are fine.
If it fails, the basics are not fine, and the investigation
starts from the first thing the test exercises.

## What we have not tested yet

One test is not a suite. We have verified one specific
specification table row. We have not verified:

- Any of the other nine rows in the spec table.
- Any of the declared laws.
- Any of the archetype inputs.
- Cross-backend equivalence.
- Overflow behavior.
- Composition with other ops.
- Any of the mutation classes the suite must kill.

The next chapter adds the rest of the hand-written suite. Each
test follows the same pattern as this one: one specific
property, one specific oracle, one specific assertion. The
patterns are mechanical; the work is in the enumeration.

Next: [Building out the suite](03-building-out.md).
