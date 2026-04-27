# Architecture

This chapter is the reference for vyre's test suite directory
layout. It describes what every directory is for, what belongs in
each, what does not, and the rationale for every boundary. It is
the chapter you will open most often once you know how to write
tests — when you have a test in mind and need to know where it
goes.

The layout is permanent. The categories defined here are the
categories vyre will have forever. New categories are not added
lightly; every category corresponds to an invariant the suite
must prove, and every invariant has been considered. If you
believe a new category is needed, the burden is on you to explain
why the existing categories cannot absorb the work.

## The top level

```
vyre/tests/
├── unit/                  Fast isolated tests with no cross-module deps
├── integration/           Full pipeline: build → validate → lower → dispatch
│   ├── primitive_ops/
│   ├── ir_construction/
│   ├── validation/
│   ├── lowering/
│   └── wire_format/
├── adversarial/           Hostile inputs, panic-free assertion
├── property/              proptest-based invariants
├── backend/               Cross-backend equivalence, determinism
├── regression/            Permanent reproducers for past bugs
├── benchmarks/            criterion-based performance gates
├── support/               Shared test utilities
└── corpus/                Committed input fixtures (fuzz seeds, round-trip)
```

Nine top-level directories. Each has a single purpose and each
corresponds to one or more invariants from
[The promises](the-promises.md).

## unit/

**Purpose:** fast, isolated tests for a single function or data
structure, with no cross-module dependencies and no pipeline
invocation.

**Scope:** tests in `unit/` do not build `ir::Program` values, do
not call `validate()`, do not lower to a backend, do not instantiate
any runtime. They exercise code in isolation — a parser, a visitor,
a data structure method — and nothing else.

**Preferred location:** inline `#[cfg(test)] mod tests { ... }` in
the source file that owns the function being tested. The
`unit/` directory exists for cases where integration test scoping
is necessary (separate target directory, no access to private items,
binary-only testing), which is rare.

**Why this boundary:** `#[cfg(test)]` modules in source files keep
the test next to the code it verifies, which is where readers look
first. Every time a test is separated from its subject, the reader
has to look in two places. Inline modules collapse that distance.
The `tests/unit/` directory exists as a fallback, not a default.

**What belongs:**
- A test for `Opcode::parse(byte) -> Option<Opcode>` that does not
  construct a Program.
- A test for `BufferAccess` field accessors that verifies getter
  behavior on synthetically constructed values.
- A test for `ValidationError::display()` formatting that constructs
  an error value directly.

**What does not belong:**
- Any test that calls `Program::builder()` or constructs an
  `ir::Program`.
- Any test that calls `lower::wgsl::lower()`.
- Any test that imports `wgpu` or any backend.
- Any test that is "like a unit test but also exercises the pipeline
  a little bit."

**Invariants served:** none specifically. Unit tests support the
rest of the suite by ensuring individual components work in
isolation. They are not the main defense for any top-level
invariant.

## integration/

**Purpose:** tests that exercise the complete
`ir::Program` → validate → lower → dispatch pipeline on specific
inputs with specific expected outputs. The bulk of vyre's
hand-written correctness coverage lives here.

Integration tests are subdivided into five subcategories, each
with its own purpose. The subdivision is not optional; every
integration test belongs to exactly one subcategory, and the
subcategory corresponds to a different aspect of the pipeline.

### integration/primitive_ops/

**Purpose:** exercise each primitive op through the complete
pipeline, with oracle-backed expected values.

**Structure:** one file per op. For the ten primitive ops currently
defined, that is ten files: `add.rs`, `and.rs`, `eq.rs`, `mul.rs`,
`not.rs`, `or.rs`, `popcount.rs`, `shl.rs`, `sub.rs`, `xor.rs`.

**Tests per file:** at least ten per op, covering:

- Every archetype that applies to the op's signature
  ([A1..A7](archetypes.md)).
- Every declared law on the op, with a specific-input test
  exercising it.
- At least one full cross-backend equivalence test.
- At least one adversarial instance (overflow, boundary).
- At least one minimum-program test (archetype S1).
- At least one long-chain test (archetype S6).

**Oracles:** specification table row, algebraic law, reference
interpreter, in that priority order.

**What belongs:** tests whose subject is one primitive op, exercised
through a complete Program, with inputs chosen from the archetype
catalog or from hand-written spec table entries.

**What does not belong:**
- Tests whose subject is a composed Program with multiple ops.
  Those belong in `ir_construction/` or `backend/`.
- Tests whose subject is the validator. Those belong in
  `validation/`.
- Tests whose subject is the lowering. Those belong in `lowering/`.
- Tests that are about cross-backend agreement without pinning a
  specific expected value. Those belong in `backend/`.

**Invariants served:** I3 (backend equivalence), I7 (law
monotonicity — via specific-input law tests), I8 (reference
agreement — via reference interpreter oracle), I11 (no panic —
implicitly, since well-formed tests must not panic).

### integration/ir_construction/

**Purpose:** tests for Program building, visiting, wire-format
encoding, and composition.

**Structure:** by concern. Files include `builders.rs` (builder
API correctness), `visitors.rs` (visit ordering and coverage),
`wire_format.rs` (encoding/decoding), `composition.rs` (multi-op
Program composition).

**What belongs:**
- A test that builds a Program using the public builder API and
  asserts the resulting structure matches an expected shape.
- A test that visits a Program and asserts every node is visited
  exactly once.
- A test that composes two Programs and asserts the composition's
  semantics match the sequential equivalent.
- A test that decodes a hand-crafted wire format buffer into an IR
  structure.

**What does not belong:**
- Validation rule tests (those go in `validation/`).
- Specific-op correctness (those go in `primitive_ops/`).
- Serialization round-trip testing for arbitrary Programs (those
  go in `property/wire_format_roundtrip.rs`; this directory is for
  specific cases, property tests are for the general case).

**Invariants served:** I2 (composition commutativity with lowering),
I4 (IR wire format round-trip identity, for specific hand-crafted cases),
I14 (non-exhaustive discipline, where enum variants are exercised
to ensure match exhaustiveness).

### integration/validation/

**Purpose:** tests for `validate(&Program)`. Every validation rule
(V001 through V020) has its own test file or test function.

**Structure:** grouped by rule family.

```
validation/
├── shadowing.rs       V-rules about variable shadowing
├── buffers.rs         V-rules about buffer declarations
├── control.rs         V-rules about control flow
├── types.rs           V-rules about type checking
├── limits.rs          V-rules about size and nesting limits
└── separability.rs    The meta-test for invariant I6
```

**Tests per rule:** at least two — one must-reject (a Program
that violates the rule, and no other rule) and one must-accept
(the reject case with the violation removed). Separability is the
property that each rule can be triggered in isolation; a rule that
cannot be triggered without also triggering another rule is a
finding.

**What belongs:**
- `test_v001_rejects_duplicate_buffer_name`
- `test_v001_accepts_distinct_buffer_names`
- `test_v013_rejects_barrier_under_divergent_control`
- A separability meta-test that iterates every `ValidationRule`
  variant and asserts each has at least one must-reject test.

**What does not belong:**
- Tests for ops that happen to validate. Those go in
  `primitive_ops/`.
- Tests for lowering behavior on valid programs. Those go in
  `lowering/`.
- Tests that assert specific error messages rather than specific
  error rules (error message stability is not a vyre invariant).

**Invariants served:** I5 (validation soundness), I6 (validation
completeness).

### integration/lowering/

**Purpose:** tests for `lower::wgsl::lower(&Program)` — the IR to
WGSL translation.

**Structure:**

```
lowering/
├── expr_coverage.rs   One test per Expr variant, asserting lowering handles it
├── node_coverage.rs   One test per Node variant
├── binop_coverage.rs  One test per BinOp variant
├── wgsl_syntax.rs     Output is valid WGSL (shader compiles on wgpu)
├── roundtrip.rs       Specific program lowers to specific shader
├── bounds_checks.rs   Every buffer access has a bounds check
└── shift_masks.rs     Every shift has a mask
```

**Meta-test:** `expr_coverage.rs` and `node_coverage.rs` each
include an enum-exhaustiveness test that enumerates the variants
and fails at compile time if a variant has no corresponding test.
Adding a new variant without coverage causes the meta-test to
fail, which forces the contributor to write the missing test.

**What belongs:**
- A test that builds a Program containing a specific `Expr`
  variant, lowers it, and asserts the output contains the expected
  WGSL construct.
- A test that lowers a Program and checks the WGSL for a bounds
  check on every buffer access.
- A test that feeds the lowered WGSL to wgpu's shader compiler and
  asserts it compiles successfully.

**What does not belong:**
- Tests that assert the lowered output equals a specific string
  byte-for-byte (those are brittle and do not survive formatting
  changes in the emitter).
- Tests for what the shader computes when dispatched — those go
  in `primitive_ops/` or `backend/`.
- Tests that specific functions are called during lowering
  (implementation details, not behavior).

**Invariants served:** I3 (backend equivalence, indirectly — the
lowering must preserve semantics), I12 (no undefined behavior —
via bounds check and shift mask coverage).

### integration/wire_format/

**Purpose:** tests for wire format ↔ IR conversion and round-trip
identity.

**Structure:**

```
wire_format/
├── from_wire.rs       Each wire tag to IR conversion
├── to_wire.rs         Each IR shape to wire format
├── roundtrip.rs       Program → bytes → Program equality for corpus
├── tag_coverage.rs    Meta-test: every WireTag variant is tested
└── constraints.rs     Legacy constraint encoding tests (to be merged)
```

**Coverage requirement:** every wire tag in the IR wire format must
have at least one `from_wire` test. Every IR shape that has a wire format
form must have at least one `to_wire` test. The round-trip
file uses a corpus of Programs from `corpus/wire_format/` and asserts
identity over the full set.

**What belongs:**
- A test that decodes a specific wire format sequence to an IR
  structure and asserts the structure matches expected.
- A test that encodes an IR structure to wire format and asserts the
  bytes match expected.
- A test that round-trips a corpus entry and asserts identity.

**What does not belong:**
- IR wire format schema validation — vyre's wire format is schema-free;
  malformed wire-format bytes are caught by decoder errors, not schemas.
- IR wire format execution semantics — wire format is serialization, not an
  executable. Tests that "run wire format" are misunderstanding the
  architecture.

**Invariants served:** I4 (IR wire format round-trip identity).

## adversarial/

**Purpose:** hostile inputs, resource bombs, malformed IR and
wire format, OOM and fault injection. The category where every test's
assertion is "graceful error handling, no panic, no undefined
behavior."

**Structure:**

```
adversarial/
├── malformed_ir.rs        Corrupted Program structures
├── malformed_wire_format.rs  Truncated or invalid wire format
├── oom.rs                 Allocation exhaustion
├── resource_bombs.rs      Deeply nested, extremely wide
├── oob_indices.rs         Buffer access at boundaries
├── panic_probes.rs        Inputs engineered from past panics
└── fuzz_corpus.rs         Replay of inputs from fuzz corpus
```

**The assertion rule:** every adversarial test asserts "did not
panic and returned a structured error." Nothing more specific. The
test does not assert what error was returned; it asserts the
runtime survived.

**What belongs:**
- A test that passes a Program with 10,000 nested conditionals and
  asserts the validator rejects it without panicking.
- A test that passes malformed wire-format bytes and asserts the
  decoder returns `DecodeError::Truncated` without panicking.
- A test that runs with OOM injection and asserts allocation
  failures are reported as structured errors.

**What does not belong:**
- Tests that assert specific error messages (brittle; not in
  scope).
- Tests that assert specific error rules (those go in
  `validation/`, where the goal is to pin down which rule fired).
- Tests for normal behavior on normal inputs (those go in
  `integration/`).

**The fuzz corpus subdirectory:** `fuzz_corpus.rs` replays inputs
from `corpus/fuzz/` — inputs discovered by `cargo fuzz` runs that
caused panics in past versions of vyre. Every entry in the corpus
is a permanent regression against panic. The file loads the
corpus at test time and asserts every input returns without
panic.

**Invariants served:** I10 (bounded allocation), I11 (no panic),
I12 (no undefined behavior — via OOB and malformed inputs).

## property/

**Purpose:** proptest-based invariant tests. Each file is one
invariant and one proptest.

**Structure:**

```
property/
├── determinism.rs           I1: same inputs → same outputs
├── wire_format_roundtrip.rs I4: roundtrip is identity
├── validation_soundness.rs  I5: validated → safe to lower
├── lowering_invariants.rs   Lowering produces valid WGSL for all validated Programs
└── law_preservation.rs      I7: composition preserves laws
```

**Seed discipline:** every proptest has a fixed seed set via
`ProptestConfig`. Failing cases are committed to
`proptest-regressions/` at the crate root and become permanent
regressions.

**Case count:** normal CI runs execute each proptest with 1,000
cases for speed. Release CI runs execute each with 100,000 cases
(these are marked `#[ignore]` and invoked separately). Nightly
runs execute each with 1,000,000 cases.

**What belongs:**
- A proptest that generates random valid Programs and asserts
  running them twice produces the same output.
- A proptest that generates arbitrary Programs, encodes them to
  wire format, decodes them back, and asserts equality.
- A proptest that generates valid Programs, validates them, lowers
  them, and asserts the lowered shader compiles.

**What does not belong:**
- Specific-input tests masquerading as property tests. Those are
  integration tests; stop using proptest for them.
- Property tests without fixed seeds. Those are rejected at
  review.
- Properties that are restatements of the implementation ("the
  output has the same length as the input" without reason).

**Invariants served:** I1, I4, I5, I7 — and any other invariant
that can be expressed as a universal quantification.

## backend/

**Purpose:** cross-backend equivalence tests. Proves I3.

**Structure:**

```
backend/
├── wgpu_vs_cpu.rs                 wgpu backend vs cpu reference fn
├── wgpu_vs_reference_interp.rs    wgpu backend vs reference interpreter
├── reference_cpu_agreement.rs     I8: reference interp agrees with cpu ref
├── determinism_across_runs.rs     I1: same run, many iterations
└── cross_backend_smoke.rs         Every backend on every canonical Program
```

**The skip rule:** if only one backend is registered, tests in
`backend/` that require multiple backends skip with a clear
reason message. They do not silently pass (which would hide
missing coverage). They do not fail (which would cause spurious
failures on single-backend development machines). They skip with
"`needs ≥ 2 backends`" printed to the test output.

**What belongs:**
- A test that runs a canonical Program on every registered backend
  and asserts identical output.
- A test that runs the same Program 1,000 times on the same
  backend and asserts identical output.
- A test that verifies the reference interpreter matches the CPU
  reference function for every op on a witnessed input sample.

**What does not belong:**
- Tests for specific op correctness on a single backend — those
  go in `primitive_ops/`.
- Tests for shader syntax — those go in `integration/lowering/`.
- Tests that only run on one backend — those are not cross-backend
  tests and belong elsewhere.

**Invariants served:** I1, I3, I8.

## regression/

**Purpose:** permanent reproducers for every bug that has ever
been fixed in vyre.

**Structure:** one file per bug. Files are named
`YYYY-MM-DD-short-description.rs`. Files are ordered by date in
directory listings.

**File format:** every file starts with a header comment recording:

```rust
//! Regression: YYYY-MM-DD — short description
//!
//! Symptom: what went wrong from the user's perspective
//!
//! Root cause: what was actually broken
//!
//! Fixed: commit <hash> — short description of fix
```

After the header, the file contains the test itself: a Program
built with the minimal inputs that trigger the bug, a run that
asserts the correct behavior. The test would have failed before
the fix; it passes after.

**The regression rule:** files in `regression/` are never deleted.
When a regression test starts failing, the bug has returned. The
fix is to the code, never to the test. This is non-negotiable and
is enforced by the review checklist.

**What belongs:**
- A file per fixed bug, with the header and a test.
- Corpus files imported from external sources when they
  reproducibly identify a past bug.

**What does not belong:**
- Tests that are not tied to a specific past bug. Those belong in
  other categories.
- Tests that no longer exercise the bug they were added for (if
  the codebase changed such that the test no longer tests what it
  was meant to test, add a new regression, do not edit the old
  one).

**Invariants served:** none specifically. Regression tests support
the rest of the suite by pinning down past bugs forever.

## benchmarks/

**Purpose:** criterion-based performance regression gates. Not
correctness tests.

**Structure:**

```
benchmarks/
├── construction.rs   Program construction perf
├── validation.rs     validate() perf
├── lowering.rs       lower::wgsl perf
├── dispatch.rs       End-to-end dispatch perf
└── wire_format.rs   encode/decode perf
```

**Baseline discipline:** every benchmark has a committed baseline.
CI runs compare each benchmark's current time to the baseline and
fail if any benchmark regresses by more than 10% without an
explicit override label on the PR.

**What belongs:**
- Benchmarks that measure vyre's performance on representative
  workloads.
- Benchmarks that represent real user use cases (e.g., a Program
  with the shape a Karyx consumer actually dispatches).

**What does not belong:**
- Correctness assertions. A benchmark that asserts the output
  equals some value is half a correctness test and half a
  benchmark; split it.
- Microbenchmarks for Rust code that has no effect on vyre's
  observable behavior. Those are not worth the CI cost.

**Invariants served:** none. Performance is not an invariant in
the sense used in this book; it is a quality attribute with
regression detection.

## support/

**Purpose:** shared test utilities used by multiple test files.

**Structure:**

```
support/
├── mod.rs          Top-level re-exports
├── programs.rs     Pre-built ir::Program factories
├── backends.rs     Backend harness wrappers
├── oracles.rs      Oracle helpers (spec table lookup, law assertions)
└── fixtures.rs     Static test data
```

**The rule:** helpers exist to reduce boilerplate, not to obscure
test intent. A test that uses a helper should read as clearly as
a test that inlines the helper. If the helper's name does not
tell the reader what is happening, the helper is wrong.

**What belongs:**
- `build_single_op(op, args)` — factory for minimal Programs.
- `run_on_default_backend(program)` — dispatch wrapper.
- `spec_table_lookup(op, inputs)` — oracle helper that looks up a
  spec table row.
- `assert_law(law, op, inputs)` — oracle helper that verifies a
  declared law on specific inputs.

**What does not belong:**
- Factories that take so many parameters the call site is longer
  than the inlined code would be.
- Helpers that hide what op is being tested, what inputs are
  being used, or what the expected value is. Those obscure test
  intent.
- Implementation utilities that should live in vyre's own source
  tree instead of its test tree.

## corpus/

**Purpose:** committed input fixtures used by multiple tests.

**Structure:**

```
corpus/
├── wire_format/    Round-trip corpus for wire_format/roundtrip.rs
├── fuzz/        Inputs from past cargo-fuzz runs that caught bugs
└── external/    Inputs imported from external conformance suites
```

**The rule:** corpus files are authoritative for their specific
inputs. Editing a corpus file requires a review rationale. Adding
a corpus file requires a source citation (where the input came
from, why it is in the corpus).

## proptest-regressions/

Not under `tests/` but at the crate root: `vyre/proptest-regressions/`.
When a proptest fails, proptest records the failing input in a
regression file. The file must be committed so the regression is
permanent. See [Seed discipline](discipline/seed-discipline.md).

## tests_generated/

This directory does not exist in `vyre/`. It exists in
`vyre-conform/tests_generated/` and is gitignored. Generated tests
are materialized at build time from the specification and are not
committed. They run alongside hand-written tests but are managed
entirely by vyre-conform. See
[vyre-conform/two-tier-suite.md](vyre-conform/two-tier-suite.md).

## The rule for "where does this test go"

When you have a test in mind and do not know where it goes, the
decision tree in [Writing/decision-tree.md](writing/decision-tree.md)
is the authority. But for reference, the short version is:

1. Does it build `ir::Program` and run the pipeline? → `integration/`.
2. Is it about a single primitive op? → `integration/primitive_ops/`.
3. Is it about Program building, visiting, or encoding? →
   `integration/ir_construction/`.
4. Is it about validation rules? → `integration/validation/`.
5. Is it about lowering to WGSL? → `integration/lowering/`.
6. Is it about wire format conversion? → `integration/wire_format/`.
7. Is the input hostile and the assertion "no panic"? →
   `adversarial/`.
8. Is it a forall proptest? → `property/`.
9. Is it about agreement between backends? → `backend/`.
10. Is it a reproducer for a specific past bug? → `regression/`.
11. Is it measuring performance? → `benchmarks/`.
12. Is it a shared helper? → `support/`.
13. None of the above? → read Part V and the decision tree.
    If it still does not fit, you are either testing something
    that does not need to be tested, or the suite has a gap that
    warrants a new category. Open a PR against this book before
    adding the test.

## The file-level layout

Every test file begins with a module-level doc comment stating
what the file is for. Every test function has a one-line doc
comment stating what it verifies and which oracle it uses. This is
not optional; it is enforced by the review checklist.

```rust
//! Tests for BinOp::Add via the full ir::Program → lower → dispatch
//! path.
//!
//! Oracles: specification table (hand-written), laws (Commutative,
//! Associative, Identity(0)), cross-backend equivalence.

use vyre::ir::{Program, Expr, Node, DataType, BinOp};
use vyre::lower::wgsl;

use crate::support::programs::build_single_binop;
use crate::support::backends::run_on_default_backend;

/// Add of (0, 0) is 0. Oracle: SpecRow from vyre-conform spec table.
#[test]
fn test_add_zero_zero_spec_table() {
    let program = build_single_binop(BinOp::Add, 0u32, 0u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0u32);
}
```

Short, readable, self-contained. The reader knows what is being
tested, what the oracle is, and what the assertion is, in under
fifteen lines.

## Summary

Nine top-level directories, each with a single purpose, each
serving specific invariants. Subdirectories under `integration/`
split that category into five distinct concerns. Every test lives
in exactly one place, and the place is determined mechanically by
the decision tree in Part V. Files have doc comments stating
intent. Tests have doc comments stating oracles. Helpers reduce
boilerplate without hiding intent. Regression files are permanent.
Corpora are authoritative.

This is the layout. It is permanent. Part III's category chapters
go into each category in depth; this chapter was the map.

Next: Part III opens with [Unit tests](categories/unit.md).
