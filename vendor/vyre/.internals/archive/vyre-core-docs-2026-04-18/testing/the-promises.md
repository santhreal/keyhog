# The promises

vyre makes fifteen promises to its users. Each promise is an
invariant the test suite must prove. This chapter presents each
promise as a statement a user can rely on, explains what would break
if the promise were broken, and names the part of the suite
responsible for keeping it. The numbering matches the invariant
identifiers used throughout vyre's source tree and vyre-conform's
specification: `I1` in this chapter is the same invariant as `I1`
in any other doc or code comment.

The promises are ordered by the scope of their effect. The first
three concern execution, which affects every user immediately. The
next three concern algebra, which affects users who reason about
vyre in terms of mathematical laws. The next three concern
resources, which affect users running in production with bounded
memory and time. The final six concern extensibility and stability,
which affect users across versions.

## Execution promises

These are the promises a user experiences the first time they run a
vyre Program. If these promises are broken, the user never trusts
vyre again.

### I1 — Determinism

**The promise:** Given an `ir::Program` and a set of inputs, vyre
produces the same output bytes every time, on every run, on every
backend, on every device, today and for every future version.

This is the central promise. Everything else in vyre is instrumental
to this one. If a user runs a Program, goes away, and runs it again
with the same inputs, they get the same bytes back. If the user
copies the Program to a different machine and runs it there, they
get the same bytes back. If the user runs it in parallel on a
cluster of heterogeneous GPUs, every node produces the same bytes.
If the user serializes the Program and a colleague runs it a decade
later on hardware that did not exist when the Program was written,
they still get the same bytes.

The test suite proves this through determinism stress tests
(`tests/property/determinism.rs` runs large Program populations many
times each), cross-run consistency tests (`tests/backend/determinism_across_runs.rs`
runs curated Programs a thousand times), and the strict-lowering
discipline that forbids every optimization that could introduce
nondeterminism.

When this promise is threatened, the fix is at the IR level: either
forbid the operation that introduced the nondeterminism, or add a
validation rule that rejects the Program that would have exhibited
it, or constrain the lowering so the nondeterministic path cannot
be emitted. Fixing nondeterminism at the backend level is a patch,
not a solution; the next backend implementer will reintroduce it.

### I2 — Composition commutativity with lowering

**The promise:** Composing two Programs and then lowering the
composition produces the same semantics as lowering each Program
individually and then threading state between them. The order of
compose-then-lower and lower-then-compose is interchangeable.

This promise matters because vyre's users build pipelines. A user
has a Program that preprocesses data, a Program that runs an
analysis, a Program that formats output. They compose these into
one. They expect the composition to behave as if the three Programs
ran in sequence. If composition changes behavior, the user cannot
build abstractions; every composition becomes a new Program with
unknown semantics.

The test suite proves this through composition tests
(`tests/integration/ir_construction/`) that build composed Programs
with known components and assert the composed behavior equals the
sequential behavior. Violations are caught at the lowering level by
the reference interpreter oracle: the composed Program is lowered
to a shader, the sequential equivalent is lowered to shaders, both
are run, and the outputs are diffed.

### I3 — Backend equivalence

**The promise:** For every Program, every pair of conformant
backends produces byte-identical results.

This is the specification-writer's promise: the specification is
unambiguous enough that two independent implementations arrive at
the same answer. If backend A and backend B disagree on any Program,
one of them is non-conformant, and the specification is the arbiter.
The user does not need to know which backend is running; any
conformant backend produces the canonical bytes.

The test suite proves this through the backend equivalence category
(`tests/backend/wgpu_vs_reference_interp.rs` and every cross-backend
file) which runs every test's Program through every registered
backend and asserts agreement to the byte. The reference interpreter
serves as the ground-truth backend; a conformance failure in any
other backend is a backend bug, and the failing input becomes a
regression test until the bug is fixed.

## Algebra promises

These are the promises to users who reason about vyre formally. When
a user declares an op has a law, that law is a commitment vyre makes
about mathematics.

### I7 — Law monotonicity

**The promise:** When you compose operations, the laws of the
composition are at least as strong as the laws the composition
theorems prove from the component operations.

If `f` is commutative and the composition pattern preserves
commutativity, then `compose(f, ...)` is commutative. vyre does not
silently lose the law. The algebra engine records the law for the
composition, and tests leverage it.

The test suite proves this through the composition theorem tests in
`tests/property/law_preservation.rs`, which generate random
compositions and verify declared laws hold after composition.

### I8 — Reference agreement

**The promise:** The reference interpreter and every CPU reference
function agree exactly, for every op, for every input, bit-exact,
forever.

The reference interpreter is the Program-level oracle. Each op's
`cpu.rs` reference function is the op-level oracle. If these two
oracles ever disagree, one of them is wrong. The test suite proves
agreement through a dedicated test in `tests/backend/reference_cpu_agreement.rs`
that runs every op through both paths on a witnessed sample of
inputs and asserts byte equality.

A disagreement between the reference interpreter and a CPU reference
is a P0 finding. The suite stops accepting new work until the
disagreement is resolved, because every other test depends on one
or both of these oracles.

### I9 — Law falsifiability

**The promise:** Every declared law on every op has at least one
test whose failure proves the law is broken. There are no decorative
law declarations.

If an op declares commutativity and no test would detect a
non-commutative implementation, the law declaration is a lie. vyre
does not tolerate decorative laws. The suite enforces this through
the mutation gate: for every declared law, a mutation in the
`LawFalselyClaim` class removes the law declaration, and at least
one test must fail. If no test fails, the law is decorative and the
finding is a test gap.

This promise is how vyre's law system stays honest as the codebase
grows.

## Resource promises

These are the promises to users running vyre in production with
bounded resources. Breaking these promises is how vyre becomes
unusable at scale.

### I10 — Bounded allocation

**The promise:** No Program allocates more than its declared buffers
plus a predictable constant per node. Dispatching a Program never
allocates unboundedly.

A user running vyre in a long-lived process needs to know that
running a Program once does not leak memory, and that running it a
million times does not accumulate memory. The allocation envelope
is declared at Program construction time; nothing exceeds it.

The test suite proves this through adversarial tests
(`tests/adversarial/resource_bombs.rs`) that feed worst-case
Programs to the pipeline and assert memory usage stays within the
declared envelope. A memory profiler runs against the suite
nightly and flags any growth beyond the expected curve.

### I11 — No panic

**The promise:** No Program, regardless of how malformed its inputs
are, can panic the vyre runtime. Malformed Programs are rejected at
validation; valid Programs running on arbitrary data return errors
instead of panicking.

A panic is a crash, and a crash in vyre becomes a crash in the
consumer. The promise of no-panic is what lets vyre be embedded in
long-running services. The test suite proves this through the
entire adversarial category: malformed IR, malformed serialized IR, OOM
injection, fault injection, resource bombs. Every adversarial test
asserts graceful error handling, never panic.

Panic-free is a property the mutation gate specifically tests for:
mutations that remove bounds checks or shift masks create panic
paths, and adversarial tests must kill those mutations.

### I12 — No undefined behavior

**The promise:** No lowered shader produces undefined behavior on
any conformant backend. Every bounds check is present, every shift
count is masked, every atomic ordering is well-defined, every
buffer access is in range.

Undefined behavior in a GPU backend is how security vulnerabilities
are born. A shader with UB can be exploited by a malicious input to
leak memory from other workgroups, corrupt the device, or worse.
vyre's promise of no-UB is a security promise as much as a
correctness promise.

The test suite proves this through the lowering coverage tests in
`tests/integration/lowering/`, which assert that every generated
shader contains the required bounds checks and shift masks. The
mutation catalog includes `LowerRemoveBoundsCheck` and
`LowerRemoveShiftMask`; any test in the lowering category must kill
these mutations. If a mutation survives, the lowering has a gap and
the suite has a hole.

## Extensibility and stability promises

These promises are about vyre's evolution over time. They are the
promises that let users depend on vyre across versions.

### I4 — IR wire format round-trip identity

**The promise:** Serializing a Program to the IR wire format and deserializing
it produces the same Program, bit-exact.

The IR wire format is vyre's binary serialization of IR. Programs are stored, transmitted,
and restored through it. If round-trip is lossy, stored Programs
silently change meaning when restored. A user who saves a Program
today and loads it next year must get the same Program back.

The test suite proves this through round-trip property tests
(`tests/property/wire_format_roundtrip.rs`) that generate random
Programs, round-trip them, and assert identity. Every new Expr or
Node variant must pass round-trip testing before it can be merged.

### I4 addendum — one semantic model

vyre has **one** semantic model: the IR. `ir::Program` is the authoritative representation of a computation. The **IR wire format** is the **binary serialization of that IR** — a compact, versioned, wire-format encoding of the same `ir::Program`, the way `.wasm` is to `.wat`, or the way a serialized protobuf is to its in-memory message.

> **Terminology note — the word "bytecode" is retired from vyre.** Earlier versions shipped a `bytecode` module that was a separate stack-machine VM. That module has been deleted. vyre has no VM, no opcode interpreter, no execution path that bypasses IR lowering. The only binary representation of a vyre program is the IR wire format.

- Programs are authored as IR (via `Program::builder()` or a frontend that emits IR).
- Programs are stored or transported as wire-format bytes (`program.to_wire()` / `Program::from_wire()`).
- Programs are executed by lowering IR to a backend (WGSL, CUDA, SPIR-V, etc.). The wire-format bytes are decoded back to IR before lowering.
- Round-trip is lossless: `from_wire(to_wire(p)) == p` for every valid `p`. This is invariant I4. A codec that loses information is a codec bug, not an accepted limitation.

I4 is therefore restated as: **IR wire format round-trip identity** — for every valid `ir::Program p`, `from_wire(to_wire(p))` equals `p` in every observable semantic detail.


### I5 — Validation soundness

**The promise:** If `validate(program)` returns empty, the Program
is safe to lower. Lowering a validated Program never panics, never
produces UB, never allocates unboundedly.

This is vyre's contract with its consumers. The consumer calls
`validate()`, gets no errors, and knows the Program can proceed.
Breaking this contract means consumers cannot rely on validation,
which means validation is decorative.

The suite proves this through a property test
(`tests/property/validation_soundness.rs`) that generates random
Programs, validates them, and runs the validated ones through the
pipeline. Any failure — a panic, a UB, an allocation violation —
is a validation gap, which becomes a new V-rule.

### I6 — Validation completeness

**The promise:** Every category of malformed Program is caught by a
validation rule. The V-rule set is complete within its declared
scope.

The companion promise to soundness. Soundness says "if validation
passes, lowering is safe." Completeness says "if lowering is
unsafe, validation catches it." Together they form the complete
contract.

The suite proves this through the V-rule separability audit
(`tests/integration/validation/separability.rs`): every V-rule
must have a test that triggers exactly that rule and no others,
and the set of V-rules must cover every malformed-Program category
that lowering cannot handle. If a malformed Program makes it past
validation and breaks lowering, that is a new V-rule plus a new
separability test.

### I13 — Userspace stability

**The promise:** A Program valid under vyre version v1.x is valid
under vyre version v1.y for every y ≥ x, and produces identical
results.

This is the "we don't break userspace" rule, inherited directly from
Linux. The user writes a Program today; that Program runs on vyre
forever, byte-identically. vyre can add operations, add data types,
add validation rules, add backends — but only in ways that do not
change the behavior of existing Programs.

The suite proves this through a cross-version test job that runs
every committed test against pinned historical vyre versions. A
divergence between versions on any test is a stability violation,
which blocks the release until resolved. The job is the guardrail;
the cultural rule is that every PR author reads the stability
section of this book before making changes that could affect I13.

### I14 — Non-exhaustive discipline

**The promise:** Every public enum in vyre is `#[non_exhaustive]`.
Adding a variant does not break existing Programs that did not use
the new variant.

The discipline that makes I13 possible. `DataType`, `BinOp`,
`UnOp`, `AtomicOp`, `BufferAccess`, `Expr`, `Node`, `Category`,
`Law`, `ValidationRule` — every one of these is non-exhaustive.
Code that matches on these enums must handle the catch-all arm,
and new variants appear without breaking the match.

The suite proves this through a build-time audit that checks every
public enum declaration in vyre and vyre-conform for the
`#[non_exhaustive]` attribute. Missing it is a compile error via a
custom lint, not a runtime warning.

### I15 — Certificate stability

**The promise:** A conformance certificate issued at vyre version
v1.x remains valid at v1.y for every y ≥ x as long as the backend
has not changed.

If vyre bumps its own version, previously certified backends do not
need to re-certify. The certificate pins down the backend's
conformance, not vyre's internal versioning. This is how vyre
supports a growing ecosystem of backends without forcing
re-certification churn.

The suite proves this through the certificate stability job that
replays historical certificates against the current vyre version
and asserts they remain valid. A certificate that becomes invalid
is a stability violation — either vyre broke its own promise or the
certificate's backend itself changed. The job distinguishes between
the two and flags the vyre bug if it is the former.

## The shape of the suite, seen through the promises

If you list the promises and ask "which test category keeps each
one," you get the shape of the suite:

| Promise | Category |
|---|---|
| I1 Determinism | property, backend |
| I2 Composition lowering | integration/ir_construction |
| I3 Backend equivalence | backend |
| I4 IR wire format round-trip | integration/wire_format, property |
| I5 Validation soundness | integration/validation, property |
| I6 Validation completeness | integration/validation/separability |
| I7 Law monotonicity | property/law_preservation |
| I8 Reference agreement | backend/reference_cpu_agreement |
| I9 Law falsifiability | mutation gate (enforced on every declared law) |
| I10 Bounded allocation | adversarial/resource_bombs |
| I11 No panic | adversarial (all subcategories) |
| I12 No undefined behavior | integration/lowering, mutation gate |
| I13 Userspace stability | cross-version CI job |
| I14 Non-exhaustive discipline | build-time audit |
| I15 Certificate stability | certificate stability CI job |

Every category has a purpose; every promise has a category keeping
it. If a promise does not map to a category, the category is missing
and the suite has a gap. If a category does not map to a promise,
the category is decorative and can be removed. The mapping is not
approximate; it is the structural skeleton of the suite.

## When a promise is broken

Every promise has a failure response defined:

- **I1 broken:** stop the line. Nondeterminism is the existential
  bug. Every in-flight PR pauses until the source is identified and
  fixed.
- **I3 broken:** the backend is non-conformant until re-certified.
  Any program depending on the disagreeing path produces incorrect
  bytes until resolved.
- **I8 broken:** P0 finding. The suite's oracles are no longer
  self-consistent. Nothing else is reliable until this is fixed.
- **I5 or I6 broken:** the validation contract is broken. Consumers
  cannot rely on validation. Fix takes priority over feature work.
- **I13 broken:** release blocker. The historical test suite is
  failing against the new version. Either the new version is wrong
  or the historical test was wrong (and the user is already
  depending on it, so the new version must match).
- **I14 broken:** build failure. A public enum lost its
  `#[non_exhaustive]`. Fix is one line and mechanical.
- **Other promises:** high-priority bug. Add a regression test, fix
  the code, ship.

The failure-response discipline is what makes the promises credible.
A promise without a response is a wish. A promise with a written,
followed response is a contract.

## Next

Part II of this book teaches the vocabulary and conceptual tools
needed to write tests that hold these promises. The next chapter is
[Vocabulary](vocabulary.md) — the precise definitions of the terms
we use throughout the book.
