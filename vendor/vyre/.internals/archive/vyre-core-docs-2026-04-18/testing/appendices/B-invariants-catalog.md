# Appendix B — Invariants catalog

vyre's fifteen invariants in full. Each entry has:

- **Name and ID.**
- **Formal statement.**
- **What it means in plain language.**
- **Test categories that defend it.**
- **What breaking it would cost.**

For context and rationale, see [the-promises.md](../the-promises.md).

---

## Execution invariants

### I1 — Determinism

**Statement:** For any `ir::Program P` and inputs `I`,
`backend.run(P, I)` produces the same output bytes on every
run, every backend, every device, every version.

**Plain language:** Same program, same inputs, same bytes,
forever. vyre's central promise.

**Defending categories:** `tests/property/determinism.rs`,
`tests/backend/determinism_across_runs.rs`, cross-backend
tests in `tests/backend/`.

**Cost of breaking:** the entire product fails. Users cannot
rely on vyre.

---

### I2 — Composition commutativity with lowering

**Statement:** For any composed Program `C = compose(A, B)`,
`lower(C)` is semantically equivalent to `lower(A) ; lower(B)`
threading state appropriately.

**Plain language:** Composing programs then lowering is the
same as lowering each program and composing the results.

**Defending categories:** `tests/integration/ir_construction/composition.rs`
and composition-related tests in `tests/integration/primitive_ops/`.

**Cost of breaking:** users cannot build pipelines. Every
composition has unpredictable semantics.

---

### I3 — Backend equivalence

**Statement:** For any `ir::Program P` and any two conformant
backends `B1, B2`, `B1.run(P, I) == B2.run(P, I)` byte-for-byte.

**Plain language:** Every backend produces identical output
for the same program. Portability is real.

**Defending categories:** `tests/backend/wgpu_vs_reference_interp.rs`,
`tests/backend/cross_backend_smoke.rs`, property tests in
`tests/property/backend_equivalence.rs`.

**Cost of breaking:** "Conformant" becomes a marketing claim.
Cross-backend deployment is unreliable.

---

## Algebra invariants

### I7 — Law monotonicity

**Statement:** If op A declares law L and B is a composition
containing A that preserves L (per composition theorems),
then B carries law L without explicit declaration.

**Plain language:** Laws propagate through valid composition.
The algebra engine does not lose them.

**Defending categories:** `tests/property/law_preservation.rs`.

**Cost of breaking:** compositional reasoning about vyre
programs fails.

---

### I8 — Reference agreement

**Statement:** For every primitive op, the reference
interpreter and the CPU reference function produce
bit-identical results for every input in the op's domain.

**Plain language:** vyre's two authoritative implementations
of every op agree perfectly.

**Defending categories:** `tests/backend/reference_cpu_agreement.rs`.

**Cost of breaking:** oracles used by cross-backend tests
become self-inconsistent. The suite's foundation crumbles.

---

### I9 — Law falsifiability

**Statement:** For every declared law on every op, the
mutation catalog contains a `LawFalselyClaim` mutation that
the test suite must kill.

**Plain language:** No decorative laws. Every declared law
is backed by at least one failing test if the declaration
were wrong.

**Defending mechanism:** mutation gate, specifically the
`LawFalselyClaim` mutation class.

**Cost of breaking:** law declarations become untrustworthy.
Tests using laws as oracles give false confidence.

---

## Resource invariants

### I10 — Bounded allocation

**Statement:** For any Program P, total allocation during
dispatch is bounded by `sum(buffers) + workgroup_mem +
O(nodes)`.

**Plain language:** No unbounded memory growth from any
program.

**Defending categories:** `tests/adversarial/resource_bombs.rs`,
nightly memory profiler job.

**Cost of breaking:** vyre cannot be embedded in
resource-constrained environments. Cloud services OOM.

---

### I11 — No panic

**Statement:** For any Program P (malformed or well-formed)
and any inputs, the runtime does not panic. Malformed
programs are rejected with errors; well-formed programs
complete or return errors.

**Plain language:** vyre never crashes. Ever. On any input.

**Defending categories:** `tests/adversarial/*`, fuzz
corpus replay.

**Cost of breaking:** vyre cannot be embedded in
long-running services. Consumers crash with vyre.

---

### I12 — No undefined behavior

**Statement:** No lowered shader produces undefined behavior
on any conformant backend. Every bounds check is present,
every shift is masked, every atomic is well-ordered.

**Plain language:** vyre's output is always safe to execute.
No memory corruption, no vulnerabilities.

**Defending categories:** `tests/integration/lowering/bounds_checks.rs`,
`tests/integration/lowering/shift_masks.rs`, mutation
catalog classes for `LowerRemove*`.

**Cost of breaking:** security vulnerabilities in vyre
users' systems.

---

## Extensibility invariants

### I4 — IR wire format round-trip identity

**Statement:** For any valid Program P, `from_wire(to_wire(P)) == P`
byte-for-byte.

**Plain language:** Serializing a program to disk and
loading it back produces the exact same program.

**Defending categories:** `tests/integration/wire_format/roundtrip.rs`,
`tests/property/wire_format_roundtrip.rs`.

**Cost of breaking:** stored programs silently change
meaning between save and load. Data loss.

See the I4 addendum ([the-promises.md#i4-addendum](../the-promises.md#i4-addendum)): vyre has exactly one semantic model (the IR). The IR wire format is its lossless binary serialization. There is no second program format, no wire-format interpreter, no execution path that bypasses IR.

---

### I5 — Validation soundness

**Statement:** If `validate(P)` returns an empty error list,
then `lower(P)` does not panic, produce UB, or allocate
unboundedly for any input.

**Plain language:** If vyre says your program is valid, it
runs safely.

**Defending categories:** `tests/property/validation_soundness.rs`.

**Cost of breaking:** the validation contract is broken.
Consumers cannot trust `validate()`'s result.

---

### I6 — Validation completeness

**Statement:** For every malformed Program category that
lowering cannot handle, at least one V-rule rejects it.
Additionally, every V-rule is independently triggerable.

**Plain language:** If a program is malformed, validation
catches it. Every rule stands on its own.

**Defending categories:** `tests/integration/validation/separability.rs`,
`tests/integration/validation/*`.

**Cost of breaking:** malformed programs slip past
validation and crash downstream. The contract is broken
in the other direction from I5.

---

### I13 — Userspace stability

**Statement:** A Program valid under vyre version v1.x is
valid under every v1.y where y >= x and produces identical
output.

**Plain language:** Once your program works with vyre, it
works with every future compatible version. "We don't
break userspace."

**Defending mechanism:** cross-version CI job running
historical test suites against current vyre.

**Cost of breaking:** users cannot upgrade vyre without
auditing every program. Adoption stalls.

---

### I14 — Non-exhaustive discipline

**Statement:** Every public enum in vyre and vyre-conform
is `#[non_exhaustive]`. Adding variants does not break
existing matches with catch-all arms.

**Plain language:** vyre can add new features without
breaking downstream consumers.

**Defending mechanism:** build-time lint that rejects
public enums without `#[non_exhaustive]`.

**Cost of breaking:** every new feature becomes a breaking
change. Velocity stalls.

---

### I15 — Certificate stability

**Statement:** A conformance certificate issued for backend
B at vyre version v1.x remains valid at v1.y >= v1.x as
long as B has not changed.

**Plain language:** Certified backends stay certified
through vyre's own version changes, as long as they
themselves don't change.

**Defending mechanism:** certificate stability CI job that
replays historical certificates against current vyre.

**Cost of breaking:** every vyre update forces backend
re-certification. The ecosystem cannot scale.

---

## Mapping invariants to test categories

| Invariant | Primary categories |
|---|---|
| I1 Determinism | property, backend |
| I2 Composition lowering | integration/ir_construction |
| I3 Backend equivalence | backend |
| I4 IR wire format round-trip | integration/wire_format, property |
| I5 Validation soundness | integration/validation, property |
| I6 Validation completeness | integration/validation/separability |
| I7 Law monotonicity | property/law_preservation |
| I8 Reference agreement | backend/reference_cpu_agreement |
| I9 Law falsifiability | mutation gate (LawFalselyClaim) |
| I10 Bounded allocation | adversarial/resource_bombs |
| I11 No panic | adversarial (all subcategories) |
| I12 No UB | integration/lowering, mutation gate |
| I13 Userspace stability | cross-version CI job |
| I14 Non-exhaustive discipline | build-time audit |
| I15 Certificate stability | certificate stability CI job |

Every invariant has a defender. Every defender has an
invariant to defend. If the mapping ever becomes
incomplete, the missing entry is a gap in vyre's quality
assurance.
